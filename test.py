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

# Load environment and initialize Flask
load_dotenv()
app = Flask(__name__)

# Email configuration
EMAIL_SENDER = os.getenv('EMAIL_SENDER')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')
SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = int(os.getenv('SMTP_PORT'))

# File paths
LOG_FILE = 'login_data.csv'
FAILED_FILE = 'failed_logins.csv'
USERS_FILE = 'users.json'
SIGNUP_FILE = 'signup_data.csv'
SUCCESSFUL_LOGINS_FILE = 'successful_logins.csv'

# Ensure CSV headers
if not os.path.exists(SUCCESSFUL_LOGINS_FILE):
    with open(SUCCESSFUL_LOGINS_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Username", "IP Address", "Last Successful Login"])

if not os.path.exists(SIGNUP_FILE):
    with open(SIGNUP_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Username", "Email", "Phone", "Hashed Password"])

if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            "Username", "Source IP", "Destination IP", "Timestamp",
            "OS Name", "Browser Info", "Login Status",
            "City", "State", "Country", "Latitude", "Longitude",
            "Failed Login Count", "Previous Successful Login", "Network Latency (ms)", "Capture File",
            "Source Port", "Destination Port", "Protocol Type",
            "Flow Duration", "Packet Size",
            "Flow Bytes per Second", "Flow Packets per Second",
            "Total Forward Packets", "Total Backward Packets",
            "IAT Forward", "IAT Backward",
            "Idle Duration", "Total Packets", "Total Bytes",
            "Packet Length Mean Forward", "Packet Length Mean Backward"
        ])

# Utility functions

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


def load_failed_logins():
    data = {}
    if os.path.exists(FAILED_FILE):
        with open(FAILED_FILE, 'r') as f:
            for row in csv.reader(f):
                if row:
                    data[row[0]] = int(row[1])
    return data


def save_failed_logins(data):
    with open(FAILED_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        for k, v in data.items():
            writer.writerow([k, v])


failed_login_tracker = load_failed_logins()


def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}


user_db = load_users()


def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)


successful_login_tracker = {}

def load_successful_logins():
    data = {}
    if os.path.exists(SUCCESSFUL_LOGINS_FILE):
        with open(SUCCESSFUL_LOGINS_FILE, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                data[(row['Username'], row['IP Address'])] = row['Last Successful Login']
    return data


successful_login_tracker = load_successful_logins()


def save_successful_logins(data):
    with open(SUCCESSFUL_LOGINS_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Username", "IP Address", "Last Successful Login"])
        for (u, ip), ts in data.items():
            writer.writerow([u, ip, ts])


def get_client_ip(req):
    if req.headers.getlist("X-Forwarded-For"):
        return req.headers.getlist("X-Forwarded-For")[0].split(',')[0]
    return req.remote_addr


def reverse_geocode(lat, lon):
    try:
        resp = requests.get("https://nominatim.openstreetmap.org/reverse",
                            params={"lat": lat, "lon": lon, "format": "json"},
                            headers={"User-Agent": "ztna-app"})
        addr = resp.json().get('address', {})
        return (addr.get('city') or addr.get('town') or addr.get('village') or 'N/A',
                addr.get('state', 'N/A'), addr.get('country', 'N/A'))
    except:
        return 'N/A', 'N/A', 'N/A'


def get_device_info(ua_str):
    ua = user_agents.parse(ua_str)
    return f"{ua.os.family} {ua.os.version_string}", f"{ua.browser.family} {ua.browser.version_string}"


def get_valid_tshark_interface():
    try:
        res = subprocess.run(['tshark', '-D'], stdout=subprocess.PIPE, text=True)
        for line in res.stdout.splitlines():
            if any(x in line.lower() for x in ['wi-fi', 'wifi', 'ethernet', 'lan', 'wireless']):
                return line.split('.')[0].strip()
    except:
        pass
    return None


def capture_network_traffic(user, duration=5):
    iface = get_valid_tshark_interface()
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    os.makedirs('captures', exist_ok=True)
    fname = f"captures/{user}_{ts}.pcapng"
    try:
        subprocess.run([r"C:\Program Files\Wireshark\tshark.exe", "-i", iface, "-a", f"duration:{duration}", "-w", fname], check=True)
    except:
        fname = "CaptureError"
    return fname


def estimate_network_latency(pcap_file):
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
        syn_time = synack_time = None
        for line in lines:
            parts = line.split('\t')
            if len(parts) == 3:
                t_rel, syn_flag, ack_flag = parts
                if syn_flag == '1' and ack_flag == '0':
                    syn_time = float(t_rel)
                elif syn_flag == '1' and ack_flag == '1':
                    synack_time = float(t_rel)
                if syn_time and synack_time:
                    break
        if syn_time and synack_time:
            return round((synack_time - syn_time) * 1000, 2)
    except:
        pass
    return "N/A"


def extract_flow_features_with_directions(pcap_file):
    try:
        res = subprocess.run([
            r"C:\Program Files\Wireshark\tshark.exe",
            "-r", pcap_file,
            "-T", "fields",
            "-e", "ip.src",
            "-e", "_ws.col.Protocol",
            "-e", "frame.len",
            "-e", "frame.time_relative"
        ], capture_output=True, text=True, check=True)
        lines = [l for l in res.stdout.strip().split('\n') if l]
        if not lines:
            return {}
        # Initialize
        total_bytes = total_pkts = 0
        times = fwd_times = bwd_times = []
        fwd_sizes = bwd_sizes = []
        src_ips = []
        for ln in lines:
            parts = ln.split('\t')
            src, proto, flen, t_rel = parts
            size = int(flen) if flen else 0
            t = float(t_rel) if t_rel else 0
            total_bytes += size
            total_pkts += 1
            times.append(t)
            src_ips.append(src)
        initiator = src_ips[0]
        for ln in lines:
            src, proto, flen, t_rel = ln.split('\t')
            size = int(flen) if flen else 0
            t = float(t_rel) if t_rel else 0
            if src == initiator:
                fwd_times.append(t)
                fwd_sizes.append(size)
            else:
                bwd_times.append(t)
                bwd_sizes.append(size)
        duration = max(times) - min(times) if times else 0
        bps = total_bytes / duration if duration else 0
        pps = total_pkts / duration if duration else 0
        mean_fwd = round(sum(fwd_sizes)/len(fwd_sizes),2) if fwd_sizes else 0
        mean_bwd = round(sum(bwd_sizes)/len(bwd_sizes),2) if bwd_sizes else 0
        def avg_iat(lst): return round(sum([j-i for i,j in zip(sorted(lst), sorted(lst)[1:])])/max(len(lst)-1,1),6)
        iat_fwd = avg_iat(fwd_times)
        iat_bwd = avg_iat(bwd_times)
        idle = round(max([j-i for i,j in zip(sorted(times), sorted(times)[1:])]) if len(times)>1 else 0,6)
        pset = {proto.lower() for proto in [ln.split('\t')[1] for ln in lines]}
        proto_type = 'TLSv1.2' if any('tls' in p for p in pset) else 'TCP'
        return {
            "Source Port": "N/A",  # Optional: extend for port extraction
            "Destination Port": "N/A",
            "Protocol Type": proto_type,
            "Flow Duration": round(duration,3),
            "Packet Size": round(total_bytes/total_pkts,2),
            "Flow Bytes per Second": round(bps,2),
            "Flow Packets per Second": round(pps,2),
            "Total Forward Packets": len(fwd_times),
            "Total Backward Packets": len(bwd_times),
            "IAT Forward": iat_fwd,
            "IAT Backward": iat_bwd,
            "Idle Duration": idle,
            "Total Packets": total_pkts,
            "Total Bytes": total_bytes,
            "Packet Length Mean Forward": mean_fwd,
            "Packet Length Mean Backward": mean_bwd
        }
    except Exception as e:
        print(f"Error extracting flow features: {e}")
        return {}

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','').strip()
        latitude = request.form.get('latitude','N/A')
        longitude = request.form.get('longitude','N/A')
        user = user_db.get(username)
        sess_key = f"session_{username}"
        failed_count = failed_login_tracker.get(sess_key,0)
        if user and bcrypt.checkpw(password.encode(), user['password'].encode()):
            login_status = 'Success'
            failed_count = 0
            failed_login_tracker.pop(sess_key,None)
            # send_email(...)  # optional notification
        else:
            login_status = 'Failure'
            failed_count += 1
            failed_login_tracker[sess_key] = failed_count
            failed_login_tracker[username] = failed_login_tracker.get(username,0)+1
        save_failed_logins({k:v for k,v in failed_login_tracker.items() if not k.startswith('session_')})
        cap = capture_network_traffic(username)
        src_ip = get_client_ip(request)
        dest_ip = '127.0.0.1'
        flow_feats = extract_flow_features_with_directions(cap)
        os_name, browser_info = get_device_info(request.headers.get('User-Agent',''))
        city, state, country = reverse_geocode(latitude, longitude)
        latency_ms = estimate_network_latency(cap)
        prev_login = successful_login_tracker.get((username, src_ip),'First Login')
        if login_status=='Success':
            successful_login_tracker[(username,src_ip)] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            save_successful_logins(successful_login_tracker)
        with open(LOG_FILE,'a',newline='') as f:
            writer=csv.writer(f)
            writer.writerow([
                username, src_ip, dest_ip, datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                os_name, browser_info, login_status,
                city, state, country, latitude, longitude,
                failed_count, prev_login, latency_ms, cap,
                flow_feats.get("Source Port"), flow_feats.get("Destination Port"), flow_feats.get("Protocol Type"),
                flow_feats.get("Flow Duration"), flow_feats.get("Packet Size"), flow_feats.get("Flow Bytes per Second"),
                flow_feats.get("Flow Packets per Second"), flow_feats.get("Total Forward Packets"), flow_feats.get("Total Backward Packets"),
                flow_feats.get("IAT Forward"), flow_feats.get("IAT Backward"), flow_feats.get("Idle Duration"),
                flow_feats.get("Total Packets"), flow_feats.get("Total Bytes"), flow_feats.get("Packet Length Mean Forward"),
                flow_feats.get("Packet Length Mean Backward")
            ])
        return "Login Successful" if login_status=='Success' else "Login Failed. Please try again."
    return render_template('login.html')

@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method=='POST':
        username=request.form['username']
        email=request.form['email']
        phone=request.form['phone']
        password=request.form['password']
        hashed=bcrypt.hashpw(password.encode(),bcrypt.gensalt()).decode()
        user_db[username]={'email':email,'password':hashed}
        save_users(user_db)
        with open(SIGNUP_FILE,'a',newline='') as f:
            writer=csv.writer(f)
            writer.writerow([username,email,phone,hashed])
        # send_email(...)  # optional confirmation
        return redirect(url_for('login'))
    return render_template('signup.html')

if __name__=='__main__':
    app.run(debug=True)
