from graph_analysis import run_graph_analysis
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
from datetime import datetime, timedelta
import pandas as pd
import joblib
from risk_score_utils import get_anomaly_score
from xgboost_label import predict_label
import re
import pyotp, qrcode, io, base64
import random
from email.mime.multipart import MIMEMultipart
from pybloom_live import BloomFilter
import pickle 
from admin import admin_bp


load_dotenv()
app = Flask(__name__)
app.secret_key = 'your-very-secret-key'
# iso_forest_model = joblib.load('iso_forest.joblib')
#xgb_model = joblib.load("xgboost_classifier.pkl")
# ——— Initialize Bloom filter ———
def save_bloom_filter(bloom, filename='bloom_filter.pkl'):
    with open(filename, 'wb') as f:
        pickle.dump(bloom, f)

def load_bloom_filter(filename='bloom_filter.pkl'):
    if os.path.exists(filename):
        with open(filename, 'rb') as f:
            return pickle.load(f)
    return BloomFilter(capacity=100_000, error_rate=0.001)

EMAIL_SENDER = os.getenv('EMAIL_SENDER')       #Your_gmail_address
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')   #App_password in gmail
SMTP_SERVER = os.getenv('SMTP_SERVER')         # smtp.gmail.com
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))        # port 587

my_bloom_filter = load_bloom_filter()

@app.route('/dashboard')
def dashboard():
    user = session.get('user', 'Unknown User')
    return render_template('dashboard.html', user=user)

def generate_email_otp():
    return str(random.randint(100000, 999999))

def send_email_otp(recipient_email, otp):
    try:
        message = MIMEMultipart()
        message['From'] = EMAIL_SENDER
        message['To'] = recipient_email
        message['Subject'] = 'ZTNA MFA TIER-1'
        body = f'Your OTP for login is: {otp}'
        message.attach(MIMEText(body, 'plain'))
        session_smtp = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        session_smtp.starttls()
        session_smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
        session_smtp.sendmail(EMAIL_SENDER, recipient_email, message.as_string())
        session_smtp.quit()
        return True
    except:
        return False

@app.route('/mfa/email', methods=['GET', 'POST'])
def mfa_email():
    if request.method == 'POST':
        otp = session.get('email_otp')
        user_input = request.form.get('otp').strip()
        if user_input == otp:
            flash('✅ Email OTP verified!', 'success')
            return redirect('/mfa/totp/setup') if session.get('require_totp') else redirect('/dashboard')
        else:
            flash('❌ Incorrect OTP. Please try again.', 'danger')
    return render_template('mfa_email.html')

@app.route('/mfa/totp', methods=['GET', 'POST'])
def mfa_totp():
    if request.method == 'POST':
        user_input = request.form.get('otp', '').strip()
        secret = session.get('totp_secret')

        if not secret:
            flash('❌ TOTP secret not found in session. Please set up again.', 'danger')
            return redirect('/mfa/totp/setup')

        totp = pyotp.TOTP(secret)
        print(f"DEBUG: TOTP secret = {secret}")
        print(f"DEBUG: User input OTP = {user_input}")

        if totp.verify(user_input, valid_window=1):
            flash('✅ TOTP verified successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('❌ Invalid TOTP.', 'danger')
    return render_template('mfa_totp.html')


@app.route('/mfa/totp/setup')
def totp_setup():
    if 'totp_secret' not in session:
        session['totp_secret'] = pyotp.random_base32()
    secret = session['totp_secret']

    # 2) Build the TOTP object & provisioning URI
    totp = pyotp.TOTP(secret)
    uri  = totp.provisioning_uri(
        name=session.get('email', 'user@example.com'),
        issuer_name="ZTNA TIER-2"
    )

    # 3) Generate QR code
    qr = qrcode.make(uri)
    buf = io.BytesIO()
    qr.save(buf, format='PNG')
    img_b64 = base64.b64encode(buf.getvalue()).decode()
    return render_template('totp_setup.html', qr_data=img_b64)

def send_email(recipient, subject, body, html_body=None):
    try:
        msg = MIMEText(html_body if html_body else body, 'html' if html_body else 'plain')
        msg['Subject'] = subject
        msg['From'] = EMAIL_SENDER
        msg['To'] = recipient

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)
    except Exception as e:
        print(f"Failed to send email: {e}")

LOG_FILE = 'cyber1_scored.csv'
FAILED_FILE = 'failed_logins.csv'
USERS_FILE = 'users.json'
SIGNUP_FILE = 'signup_data.csv'
SUCCESSFUL_LOGINS_FILE = 'successful_logins.csv'
app.register_blueprint(admin_bp)

if not os.path.exists(SUCCESSFUL_LOGINS_FILE):
    with open(SUCCESSFUL_LOGINS_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Username", "IP Address", "Last Successful Login"])

if not os.path.exists(SIGNUP_FILE):
    with open(SIGNUP_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Username", "Email", "Phone", "Hashed Password"])

failed_login_tracker = {}

if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            "Username", "Source IP", "Destination IP", "Timestamp",
            "OS Name", "Browser Info", "Login Status",
            "City", "State", "Country", "Latitude", "Longitude",
            "Failed Login Count", "Previous Successful Login", "Network Latency (ms)", "Capture File",
            "Source Port", "Destination Port", "Protocol Type",
            "Flow Duration","Active Duration", "Packet Size",
            "Flow Bytes per Second", "Flow Packets per Second",
            "Total Forward Packets", "Total Backward Packets",
            "IAT Forward", "IAT Backward",
            "Idle Duration", "Total Packets", "Total Bytes", 
            "Packet Length Mean Forward", "Packet Length Mean Backward", "Risk Score", "Severity"
        ])
        
def load_failed_logins(): 
    failed = {} 
    if os.path.exists(FAILED_FILE): 
        with open(FAILED_FILE, 'r') as f: 
            reader = csv.reader(f) 
            for row in reader: 
                if row: 
                    failed[row[0]] = int(row[1]) 
    return failed

def save_failed_logins(data): 
    with open(FAILED_FILE, 'w', newline='') as f: 
        writer = csv.writer(f) 
        for email, count in data.items(): 
            writer.writerow([email, count])

failed_login_tracker = load_failed_logins()

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)

user_db = load_users()


def get_client_ip(req): 
    if req.headers.getlist("X-Forwarded-For"): 
        ip = req.headers.getlist("X-Forwarded-For")[0].split(',')[0] 
    else: 
        ip = req.remote_addr 
    return ip

def load_successful_logins():
    successful = {}
    if os.path.exists(SUCCESSFUL_LOGINS_FILE):
        with open(SUCCESSFUL_LOGINS_FILE, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                successful[(row['Username'], row['IP Address'])] = row['Last Successful Login']
    return successful

def save_successful_logins(successful_logins):
    with open(SUCCESSFUL_LOGINS_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Username", "IP Address", "Last Successful Login"])
        for (username, ip), timestamp in successful_logins.items():
            writer.writerow([username, ip, timestamp])

successful_login_tracker = load_successful_logins()

def reverse_geocode(lat, lon):
    try:
        response = requests.get(
            f"https://nominatim.openstreetmap.org/reverse",
            params={"lat": lat, "lon": lon, "format": "json"},
            headers={"User-Agent": "my-flask-app"}
        )
        data = response.json()
        address = data.get("address", {})
        city = address.get("city") or address.get("town") or address.get("village") or "N/A"
        state = address.get("state", "N/A")
        country = address.get("country", "N/A")
        return city, state, country
    except Exception as e:
        print(f"Reverse geocode error: {e}")
        return 'N/A', 'N/A', 'N/A'

def get_device_info(user_agent_string):
    ua = user_agents.parse(user_agent_string)
    os_name = f"{ua.os.family} {ua.os.version_string}"
    browser_info = f"{ua.browser.family} {ua.browser.version_string}"
    return os_name, browser_info

def get_valid_tshark_interface():
    import subprocess
    try:
        result = subprocess.run(['tshark', '-D'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in result.stdout.splitlines():
            if any(keyword in line.lower() for keyword in ['wi-fi', 'wifi', 'ethernet', 'lan', 'wireless']):
                return line.split('.')[0].strip()
    except Exception as e:
        print(f"[!] Error detecting tshark interface: {e}")
    return None


def capture_network_traffic(email, duration=3, interface= get_valid_tshark_interface()):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    os.makedirs('captures', exist_ok=True)
    filename = f"captures/{email}_{timestamp}.pcapng"

    try:
        subprocess.run([
            r"C:\Program Files\Wireshark\tshark.exe",
            "-i", str(interface),
            "-a", f"duration:{duration}",
            "-w", filename
        ], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error capturing traffic: {e}")
        filename = "Capture Failed"
    except FileNotFoundError as e:
        print(f"tshark not found: {e}")
        filename = "Capture Not Found"
    return filename

def extract_ips_from_pcap(pcap_file):  
    try:  
        result = subprocess.run([  
            r"C:\Program Files\Wireshark\tshark.exe",  
            "-r", pcap_file,  
            "-T", "fields",  
            "-e", "ip.src",  
            "-e", "ip.dst",  
            "-Y", "ip"  
        ], capture_output=True, text=True, check=True)  
  
        ip_lines = result.stdout.strip().split("\n")  
        source_ips = []
        dest_ips = []

        for line in ip_lines:
            parts = line.split("\t")
            if len(parts) == 2:
                src, dst = parts
                if src not in ("127.0.0.1", "0.0.0.0"): source_ips.append(src)
                if dst not in ("127.0.0.1", "0.0.0.0"): dest_ips.append(dst)

        src_counter = Counter(source_ips)
        dst_counter = Counter(dest_ips)

        print("\n[+] Source IPs Count:", src_counter)
        print("\n[+] Destination IPs Count:", dst_counter)

        most_common_src = src_counter.most_common(1)[0][0] if src_counter else "N/A"
        most_common_dst = dst_counter.most_common(1)[0][0] if dst_counter else "N/A"

        return most_common_src, most_common_dst

    except subprocess.CalledProcessError as e:
        print(f"[!] Error reading pcap file: {e}")
        return "N/A", "N/A"
    except Exception as e:
        print(f"[!] Unexpected error while extracting IPs: {e}")
        return "N/A", "N/A"

def get_ips_from_request_or_pcap(request, capture_file):
    src_ip = get_client_ip(request)
    dst_ip = "127.0.0.1" 

    if capture_file and "Capture" not in capture_file:
        src_ip, dst_ip = extract_ips_from_pcap(capture_file)
    
    return src_ip, dst_ip

def estimate_network_latency(pcap_file):
    """Estimate network latency using SYN and SYN-ACK timestamps."""
    try:
        result = subprocess.run([
            r"C:\Program Files\Wireshark\tshark.exe",
            "-r", pcap_file,
            "-Y", "tcp.flags.syn == 1 && tcp.flags.ack == 0 || tcp.flags.syn == 1 && tcp.flags.ack == 1",
            "-T", "fields",
            "-e", "frame.time_relative",
            "-e", "tcp.flags.syn",
            "-e", "tcp.flags.ack"
        ], capture_output=True, text=True, check=True)

        lines = result.stdout.strip().split('\n')
        syn_time = None
        synack_time = None

        for line in lines:
            parts = line.split('\t')
            if len(parts) == 3:
                time_rel, syn_flag, ack_flag = parts
                if syn_flag == '1' and ack_flag == '0' and syn_time is None:
                    syn_time = float(time_rel)
                elif syn_flag == '1' and ack_flag == '1' and synack_time is None:
                    synack_time = float(time_rel)

                if syn_time is not None and synack_time is not None:
                    break

        if syn_time is not None and synack_time is not None:
            latency_ms = (synack_time - syn_time) * 1000
            return round(latency_ms, 2)

    except Exception as e:
        print(f"[!] Error estimating network latency: {e}")

    return "N/A"

import subprocess
from collections import Counter

def extract_flow_features_with_directions(pcap_file, login_end_time=None):
    """Extract detailed flow features with accurate packet direction and protocol detection,
       including mean packet lengths for forward/backward, and active duration."""
    try:
        # 1) First pass: per-packet fields
        tshark_fields = [
            r"C:\Program Files\Wireshark\tshark.exe",
            "-r", pcap_file,
            "-T", "fields",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.srcport",
            "-e", "udp.srcport",
            "-e", "tcp.dstport",
            "-e", "udp.dstport",
            "-e", "_ws.col.Protocol",
            "-e", "frame.len",
            "-e", "frame.time_relative"
        ]
        result = subprocess.run(tshark_fields, capture_output=True, text=True, check=True)
        lines = [l for l in result.stdout.strip().split('\n') if l]
        if not lines:
            return {}

        # initialize accumulators
        total_packets = total_bytes = 0
        timestamps = []
        fwd_ts = []; bwd_ts = []
        fwd_sz = []; bwd_sz = []
        src_ips = []; dst_ips = []
        src_ports = []; dst_ports = []
        protocols = []

        # collect all packets
        for l in lines:
            f = l.split('\t')
            if len(f) < 9: 
                continue
            src, dst, tcps, udps, tcpd, udpd, proto, pkt_len, t_rel = f
            size = int(pkt_len or 0); t = float(t_rel or 0)
            total_bytes += size; total_packets += 1
            timestamps.append(t)
            src_ips.append(src); dst_ips.append(dst)
            src_ports.append(tcps or udps); dst_ports.append(tcpd or udpd)
            protocols.append(proto)

        initiator_ip = src_ips[0]

        # split forward/backward (up to login_end_time if given)
        for l in lines:
            src, dst, *_, pkt_len, t_rel = l.split('\t')
            t = float(t_rel or 0)
            if login_end_time is not None and t > login_end_time:
                continue
            size = int(pkt_len or 0)
            if src == initiator_ip:
                fwd_ts.append(t); fwd_sz.append(size)
            else:
                bwd_ts.append(t); bwd_sz.append(size)

        # basic flow stats
        flow_duration = max(timestamps) - min(timestamps) if timestamps else 0
        flow_bps = total_bytes / flow_duration if flow_duration else 0
        flow_pps = total_packets / flow_duration if flow_duration else 0

        def avg_iat(ts_list):
            if len(ts_list) < 2:
                return 0
            st = sorted(ts_list)
            diffs = [t2 - t1 for t1, t2 in zip(st, st[1:])]
            return sum(diffs) / len(diffs)

        iat_fwd = avg_iat(fwd_ts)
        iat_bwd = avg_iat(bwd_ts)

        # idle = max gap anywhere
        idle = 0
        if len(timestamps) >= 2:
            st = sorted(timestamps)
            idle = max(t2 - t1 for t1, t2 in zip(st, st[1:]))

        mean_fwd = round(sum(fwd_sz)/len(fwd_sz),2) if fwd_sz else 0
        mean_bwd = round(sum(bwd_sz)/len(bwd_sz),2) if bwd_sz else 0

        proto_set = {p.lower() for p in protocols if p}
        protocol_type = (
            "TLSv1.2" if any("tls" in p for p in proto_set) else
            "TCP"    if any("tcp" in p for p in proto_set) else
            "UDP"    if any("udp" in p for p in proto_set) else
            "N/A"
        )

        # 2) Get Active Duration via conversation stats
        #    This uses tshark's conv,tcp summary, which reports Duration, Active, Idle per conversation.
        #    We pick the line matching our initiator<->responder pair and most common ports.
        active_dur = 0.0
        try:
            convo = subprocess.run([
                r"C:\Program Files\Wireshark\tshark.exe",
                "-r", pcap_file,
                "-q", "-z", "conv,tcp"
            ], capture_output=True, text=True, check=True).stdout

            # Compile a regex that matches lines starting with an IP, whitespace, port, etc.
            line_re = re.compile(r'^(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)'
                                r'(?:\s+\d+){4}\s+([\d\.]+)\s+([\d\.]+)\s+([\d\.]+)')
            # groups: 1=srcIP,2=srcPort,3=dstIP,4=dstPort, 5=Duration,6=Active,7=Idle

            sport = Counter(src_ports).most_common(1)[0][0] if src_ports else None
            dport = Counter(dst_ports).most_common(1)[0][0] if dst_ports else None

            for row in convo.splitlines():
                m = line_re.match(row)
                if not m:
                    continue
                s_ip, s_prt, d_ip, d_prt, _, active_s, _ = m.groups()
                # match either direction
                if ((s_ip == initiator_ip and int(s_prt) == int(sport) and
                    d_ip == dst_ips[0]    and int(d_prt) == int(dport))
                    or
                    (s_ip == dst_ips[0]    and int(s_prt) == int(dport) and
                    d_ip == initiator_ip and int(d_prt) == int(sport))
                ):
                    active_dur = float(active_s)
                    break
        except Exception:
            # silent fallback
            active_dur = 0.0

        # 2) If still zero, fallback to (flow – idle)
        if active_dur == 0 and flow_duration > 0:
            active_dur = flow_duration - idle

        return {
            "Source Port": sport or "N/A",
            "Destination Port": dport or "N/A",
            "Protocol Type": protocol_type,
            "Flow Duration": round(flow_duration, 3),
            "Active Duration": round(active_dur, 3),
            "Packet Size (mean)": round(total_bytes / total_packets, 2) if total_packets else 0,
            "Flow Bytes per Second": round(flow_bps, 2),
            "Flow Packets per Second": round(flow_pps, 2),
            "Total Forward Packets": len(fwd_ts),
            "Total Backward Packets": len(bwd_ts),
            "IAT Forward": round(iat_fwd, 6),
            "IAT Backward": round(iat_bwd, 6),
            "Idle Duration": round(idle, 6),
            "Total Packets": total_packets,
            "Total Bytes": total_bytes,
            "Packet Length Mean Forward": mean_fwd,
            "Packet Length Mean Backward": mean_bwd
        }

    except Exception as e:
        print(f"[!] Error extracting flow features: {e}")
        return {}


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # --- 1) Extract inputs ---
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        latitude = request.form.get('latitude', 'N/A').strip()
        longitude = request.form.get('longitude', 'N/A').strip()

        # --- 2) Check credentials ---
        user = user_db.get(username)
        session_key = f"session_{username}"
        current_failed_attempts = failed_login_tracker.get(session_key, 0)

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            login_status = 'Success'
        else:
            login_status = 'Failure'
            current_failed_attempts += 1
            failed_login_tracker[session_key] = current_failed_attempts
            failed_login_tracker[username] = failed_login_tracker.get(username, 0) + 1

        save_failed_logins({k: v for k, v in failed_login_tracker.items() if not k.startswith('session_')})

        # --- 3) Capture network traffic & extract features ---
        pcap_file = capture_network_traffic(username)
        source_ip, dest_ip = extract_ips_from_pcap(pcap_file)
        flow_features = extract_flow_features_with_directions(pcap_file)

        # --- 4) Risk scoring & prediction ---
        risk_score, is_anomaly = get_anomaly_score(flow_features)
        temp_features = flow_features.copy()
        temp_features['Risk Score'] = risk_score
        predicted_label = predict_label(temp_features)

        # --- 5) Device & location info ---
        user_agent = request.headers.get('User-Agent', '')
        os_name, browser_info = get_device_info(user_agent)
        city, state, country = reverse_geocode(latitude, longitude)
        network_latency_ms = estimate_network_latency(pcap_file)

        # --- 6) Previous login retrieval ---
        prev_login = successful_login_tracker.get((username, source_ip), 'First Login')

        # --- 7) Write to log ---
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
                prev_login,
                network_latency_ms,
                pcap_file,
                flow_features.get('Source Port', 'N/A'),
                flow_features.get('Destination Port', 'N/A'),
                flow_features.get('Protocol Type', 'N/A'),
                flow_features.get('Flow Duration', 'N/A'),
                flow_features.get('Active Duration', 'N/A'),
                flow_features.get('Packet Size (mean)', 'N/A'),
                flow_features.get('Flow Bytes per Second', 'N/A'),
                flow_features.get('Flow Packets per Second', 'N/A'),
                flow_features.get('Total Forward Packets', 'N/A'),
                flow_features.get('Total Backward Packets', 'N/A'),
                flow_features.get('IAT Forward', 'N/A'),
                flow_features.get('IAT Backward', 'N/A'),
                flow_features.get('Idle Duration', 'N/A'),
                flow_features.get('Total Packets', 'N/A'),
                flow_features.get('Total Bytes', 'N/A'),
                flow_features.get('Packet Length Mean Forward', 'N/A'),
                flow_features.get('Packet Length Mean Backward', 'N/A'),
                risk_score,
                predicted_label
            ])
        run_graph_analysis()


        # --- 8) Post-login logic ---
        if login_status == 'Success':
            my_bloom_filter = load_bloom_filter()
            if username in my_bloom_filter:
                return "Access Denied. You have been blocked due to suspicious activity. Please contact the ZTNA administrator to regain access.", 403
            # Determine if this is the first successful login from this IP
            first_time = (username, source_ip) not in successful_login_tracker
            # Record successful login
            successful_login_tracker[(username, source_ip)] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            save_successful_logins(successful_login_tracker)

            # Capture failure count before resetting
            f = current_failed_attempts
            # Reset session-specific failures
            current_failed_attempts = 0
            failed_login_tracker.pop(session_key, None)

            # --- 8a) MFA & redirection logic ---
            if f == 0:
                session['user'] = username
                if first_time:
                    otp = generate_email_otp()
                    session['email_otp'] = otp  # ✅ store OTP in session
                    send_email_otp(user['email'], otp)
                    return redirect(url_for('mfa_email'))
                return redirect(url_for('dashboard'))

            if 0 < f < 3:
                session['user'] = username
                if predicted_label == 1:
                    otp = generate_email_otp()
                    session['email_otp'] = otp  # ✅ store OTP in session
                    send_email_otp(user['email'], otp)
                    return redirect(url_for('mfa_email'))
                if not session.get('totp_secret'):
                    return redirect(url_for('totp_setup'))
                return redirect(url_for('mfa_totp'))

            if 3 <= f < 5:
                session['user'] = username
                if not session.get('totp_secret'):
                    return redirect(url_for('totp_setup'))
                return redirect(url_for('mfa_totp'))

            if f >= 5:
                my_bloom_filter.add(username)
                save_bloom_filter(my_bloom_filter)
                blocked_path = os.path.join(app.root_path, 'bloom_blocked.json')
                # ensure file exists
                if not os.path.exists(blocked_path):
                    with open(blocked_path, 'w') as jb:
                        json.dump([], jb)

                with open(blocked_path, 'r+') as jb:
                    data = json.load(jb)
                    if username not in data:
                        data.append(username)
                        jb.seek(0)
                        jb.truncate()
                        json.dump(data, jb)
                return "Access Denied", 403

            # Fallback: allow login
            session['user'] = username
            return redirect(url_for('dashboard'))

        # --- 9) Login failure path ---
        return "Login Failed. Please try again.", 401

    # GET handler
    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']

        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        user_db[username] = {'email': email, 'password': hashed_pw}
        save_users(user_db)

        with open(SIGNUP_FILE, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([username, email, phone, hashed_pw])
        
        send_email(
            email,
            'Signup Confirmation',
            f"Hello {username},\n\nYou have successfully signed up on our platform.",
            html_body=f"""
            <html><body>
            <h2>Welcome {username}!</h2>
            <p>You have successfully <b>signed up</b> on our ZTNA platform.</p>
            <p>Thank you for joining us!</p>
            </body></html>
            """
        )

        return redirect(url_for('login'))
    
    return render_template('signup.html')

if __name__ == '__main__':
    app.run(debug=True)
