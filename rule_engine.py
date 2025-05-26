from flask import flash, session, Flask, request, render_template, redirect, url_for
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
import csv
from datetime import datetime
import requests
import user_agents
import os
import bcrypt
import json
import subprocess
from collections import Counter
from datetime import timedelta
import pandas as pd
import joblib
from risk_score_utils import get_anomaly_score
from xgboost_label import predict_label
import re
import pyotp, qrcode, io, base64
import random
from email.mime.multipart import MIMEMultipart

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')  # Load secret key from .env for security

# -----------------------
# Import Shared State & Helpers
# -----------------------
from app import (
    user_db,
    failed_login_tracker,
    save_failed_logins,
    successful_login_tracker,
    save_successful_logins,
    get_device_info,
    reverse_geocode,
    estimate_network_latency,
    capture_network_traffic,
    extract_ips_from_pcap,
    extract_flow_features_with_directions,
    send_email_otp
)

# -----------------------
# MFA Selection Helper
# -----------------------
def select_mfa_method(current_failed: int, predicted_label: int, is_first_login: bool) -> str:
    """
    Determine which MFA route to take.

    Parameters:
    - current_failed: number of failed attempts in the current session
    - predicted_label: risk label (1 = low risk, 2 = high risk)
    - is_first_login: True if this is the user's first-ever successful login

    Returns:
    - 'email': email OTP verification
    - 'totp': TOTP verification
    - 'direct': no MFA, direct access
    - 'deny': block access

    Rules:
      1) 0 failures, first-ever login → email
      2) 0 failures, not first → direct
      3) 1–2 failures & label=1 → email
      4) 1–2 failures & label=2 → totp
      5) 3–5 failures → totp
      6) ≥6 failures → deny
    """
    # Ensure predicted_label is expected
    if predicted_label not in (1, 2):
        raise ValueError(f"Unexpected predicted_label: {predicted_label}")

    # Rule 1 & 2: No failures
    if current_failed == 0:
        if is_first_login:
            return 'email'
        return 'direct'

    # Rule 3 & 4: 1-2 failures
    if 0 < current_failed < 3:
        return 'email' if predicted_label == 1 else 'totp'

    # Rule 5: 3-5 failures
    if 3 <= current_failed < 6:
        return 'totp'

    # Rule 6: 6+ failures
    return 'deny'

# -----------------------
# Existing MFA & Helper Routines
# -----------------------

def generate_email_otp() -> str:
    return str(random.randint(100000, 999999))

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        latitude = request.form.get('latitude', 'N/A').strip()
        longitude = request.form.get('longitude', 'N/A').strip()

        user = user_db.get(username)
        current_failed_attempts = failed_login_tracker.get(f"session_{username}", 0)

        # Primary authentication
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            login_status = 'Success'
            current_failed_attempts = 0
            failed_login_tracker.pop(f"session_{username}", None)
        else:
            login_status = 'Failure'
            current_failed_attempts += 1
            failed_login_tracker[f"session_{username}"] = current_failed_attempts
            failed_login_tracker[username] = failed_login_tracker.get(username, 0) + 1

        # Persist non-session failure counts
        save_failed_logins({k: v for k, v in failed_login_tracker.items() if not k.startswith('session_')})

        # Capture & scoring
        capture_file = capture_network_traffic(username)
        source_ip, dest_ip = extract_ips_from_pcap(capture_file)
        flow_features = extract_flow_features_with_directions(capture_file)
        risk_score, is_anomaly = get_anomaly_score(flow_features)
        flow_feature_temp = flow_features.copy()
        flow_feature_temp['Risk Score'] = risk_score
        predicted_label = predict_label(flow_feature_temp)

        # Determine if first-ever login for this user+IP
        previous_success = successful_login_tracker.get((username, source_ip), 'First Login')
        is_first_login = (previous_success == 'First Login')

        # On primary auth success
        if login_status == 'Success':
            # Update last successful login
            successful_login_tracker[(username, source_ip)] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            save_successful_logins(successful_login_tracker)

            # Decide MFA path
            mfa_choice = select_mfa_method(
                current_failed=current_failed_attempts,
                predicted_label=predicted_label,
                is_first_login=is_first_login
            )

            if mfa_choice == 'email':
                otp = generate_email_otp()
                session['email_otp'] = otp
                session['user'] = username
                session['email'] = user['email']
                session['require_totp'] = (predicted_label == 2)
                send_email_otp(user['email'], otp)
                return redirect('/mfa/email')

            if mfa_choice == 'totp':
                session['user'] = username
                session['require_totp'] = True
                if not session.get('totp_secret'):
                    return redirect('/mfa/totp/setup')
                return redirect('/mfa/totp')

            if mfa_choice == 'direct':
                session['user'] = username
                return redirect('/dashboard')

            # Block access
            # bloom_filter.add(username)  # Optional: mark high-risk
            return "Access Denied – too many failures", 403

        # Log all attempts including failures
        user_agent = request.headers.get('User-Agent', '')
        os_name, browser_info = get_device_info(user_agent)
        city, state, country = reverse_geocode(latitude, longitude)
        network_latency_ms = estimate_network_latency(capture_file)

        with open(LOG_FILE, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                username,
                source_ip,
                dest_ip,
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                os_name,
                browser_info,
                login_status,
                city,
                state,
                country,
                latitude,
                longitude,
                current_failed_attempts,
                previous_success,
                network_latency_ms,
                capture_file,
                flow_features.get("Source Port", "N/A"),
                flow_features.get("Destination Port", "N/A"),
                flow_features.get("Protocol Type", "N/A"),
                flow_features.get("Flow Duration", "N/A"),
                flow_features.get("Active Duration", "N/A"),
                flow_features.get("Packet Size (mean)", "N/A"),
                flow_features.get("Flow Bytes per Second", "N/A"),
                flow_features.get("Flow Packets per Second", "N/A"),
                flow_features.get("Total Forward Packets", "N/A"),
                flow_features.get("Total Backward Packets", "N/A"),
                flow_features.get("IAT Forward", "N/A"),
                flow_features.get("IAT Backward", "N/A"),
                flow_features.get("Idle Duration", "N/A"),
                flow_features.get("Total Packets", "N/A"),
                flow_features.get("Total Bytes", "N/A"),
                flow_features.get("Packet Length Mean Forward", "N/A"),
                flow_features.get("Packet Length Mean Backward", "N/A"),
                risk_score,
                predicted_label
            ])

        return "Login Failed. Please try again."

    return render_template('login.html')

# ... rest of signup, mfa routes, etc. unchanged ...
