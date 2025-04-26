from flask import Flask, request, render_template, redirect, url_for
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


load_dotenv()
app = Flask(__name__)

EMAIL_SENDER = os.getenv('EMAIL_SENDER')       #Your_gmail_address
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')   #App_password in gmail
SMTP_SERVER = os.getenv('SMTP_SERVER')         # smtp.gmail.com
SMTP_PORT = int(os.getenv('SMTP_PORT'))        # port 587

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

LOG_FILE = 'login_data.csv'
FAILED_FILE = 'failed_logins.csv'
USERS_FILE = 'users.json'
SIGNUP_FILE = 'signup_data.csv'
SUCCESSFUL_LOGINS_FILE = 'successful_logins.csv'

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
            "User Name", "Source IP", "Destination IP", "Timestamp",
            "OS Name", "Browser Info", "Login Status",
            "City", "State", "Country", "Latitude", "Longitude",
            "Failed Login Count", "Previous Successful Login", "Network Latency (ms)", "Capture File"
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


def capture_network_traffic(email, duration=5, interface= get_valid_tshark_interface()):
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

def estimate_network_latency(pcap_file):
    try:
        result = subprocess.run([
            r"C:\Program Files\Wireshark\tshark.exe",
            "-r", pcap_file,
            "-T", "fields",
            "-e", "frame.time_relative",
            "-Y", "tcp"
        ], capture_output=True, text=True, check=True)

        timestamps = [float(line.strip()) for line in result.stdout.strip().split('\n') if line.strip()]
        if len(timestamps) >= 2:
            latency_ms = (timestamps[1] - timestamps[0]) * 1000  # milliseconds
            return round(latency_ms, 2)
    except Exception as e:
        print(f"[!] Error estimating network latency: {e}")
    return "N/A"


def get_ips_from_request_or_pcap(request, capture_file):
    src_ip = get_client_ip(request)
    dst_ip = "127.0.0.1" 

    if capture_file and "Capture" not in capture_file:
        src_ip, dst_ip = extract_ips_from_pcap(capture_file)
    
    return src_ip, dst_ip


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        latitude = request.form.get('latitude', 'N/A').strip()
        longitude = request.form.get('longitude', 'N/A').strip()

        user = user_db.get(username)
        current_failed_attempts = failed_login_tracker.get(f"session_{username}", 0)

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            login_status = 'Success'
            current_failed_attempts = 0
            failed_login_tracker.pop(f"session_{username}", None)
            send_email(
                user['email'],
                'ZTNA Login Notification',
                f"Hello {username},\n\nYou have successfully logged in at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.",
                html_body=f"""
                <html><body>
                <h2>Hello {username},</h2>
                <p>You have successfully <b>logged in</b> at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.</p>
                <p>Thank you!</p>
                </body></html>
                """
            )
        else:
            login_status = 'Failure'
            current_failed_attempts += 1
            failed_login_tracker[f"session_{username}"] = current_failed_attempts
            failed_login_tracker[username] = failed_login_tracker.get(username, 0) + 1

        save_failed_logins({k: v for k, v in failed_login_tracker.items() if not k.startswith('session_')})

        capture_file = capture_network_traffic(username)
        source_ip, dest_ip = extract_ips_from_pcap(capture_file)

        user_agent = request.headers.get('User-Agent', '')
        os_name, browser_info = get_device_info(user_agent)

        city, state, country = reverse_geocode(latitude, longitude)
        network_latency_ms = estimate_network_latency(capture_file)

        previous_successful_login = successful_login_tracker.get((username, source_ip), "First Login")

        if login_status == 'Success':
            successful_login_tracker[(username, source_ip)] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            save_successful_logins(successful_login_tracker)

        with open(LOG_FILE, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                username, source_ip, dest_ip, datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                os_name, browser_info, login_status,
                city, state, country, latitude, longitude,
                current_failed_attempts, previous_successful_login, network_latency_ms, capture_file
            ])

        return "Login Successful" if login_status == 'Success' else "Login Failed. Please try again."

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
