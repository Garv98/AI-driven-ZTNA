from flask import Flask, request, render_template, redirect, url_for
import csv
from datetime import datetime
import requests
import user_agents
import os
import bcrypt
import json
import subprocess
from datetime import datetime, timedelta


app = Flask(__name__)
LOG_FILE = 'login_data.csv'
FAILED_FILE = 'failed_logins.csv'
USERS_FILE = 'users.json'

failed_login_tracker = {}

if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            "Email Address", "Source IP", "Destination IP", "Timestamp",
            "OS Name", "Browser Info", "Login Status",
            "City", "State", "Country", "Latitude", "Longitude",
            "Failed Login Count", "Capture File"
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

def capture_network_traffic(email, duration=5, interface=4):
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
        # Extract both source and destination IPs
        result = subprocess.run([  
            r"C:\Program Files\Wireshark\tshark.exe",  
            "-r", pcap_file,  
            "-T", "fields",  
            "-e", "ip.src",  
            "-e", "ip.dst",  
            "-Y", "ip"  # Filters only IP packets  
        ], capture_output=True, text=True, check=True)  
  
        ip_lines = result.stdout.strip().split("\n")  
        source_ips = []
        dest_ips = []

        for line in ip_lines:
            src, dst = line.split("\t")
            source_ips.append(src)
            dest_ips.append(dst)

        # Remove duplicates and invalid IPs
        source_ips = list(set([ip for ip in source_ips if ip not in ("127.0.0.1", "0.0.0.0")]))
        dest_ips = list(set([ip for ip in dest_ips if ip not in ("127.0.0.1", "0.0.0.0")]))

        # Return most frequent source and destination IPs
        most_common_src = max(source_ips, key=source_ips.count) if source_ips else "127.0.0.1"
        most_common_dst = max(dest_ips, key=dest_ips.count) if dest_ips else "127.0.0.1"

        return most_common_src, most_common_dst
  
    except Exception as e:  
        print(f"[!] Error extracting IPs from pcap: {e}")  
        return "127.0.0.1", "127.0.0.1"


def get_ips_from_request_or_pcap(request, capture_file):
    src_ip = get_client_ip(request)
    dst_ip = "127.0.0.1"  # Default destination IP (can be updated based on capture)

    if capture_file and "Capture" not in capture_file:
        src_ip, dst_ip = extract_ips_from_pcap(capture_file)
    
    return src_ip, dst_ip


@app.route('/', methods=['GET', 'POST'])
def login():
    global failed_login_tracker
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        ip = get_client_ip(request) 
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        os_name, browser = get_device_info(request.headers.get('User-Agent'))
        
        latitude = request.form.get('latitude', 'N/A')
        longitude = request.form.get('longitude', 'N/A')
        
        if latitude != 'N/A' and longitude != 'N/A':
            city, state, country = reverse_geocode(latitude, longitude)
        else:
            city, state, country = 'N/A', 'N/A', 'N/A'

        capture_file = capture_network_traffic(email)

        # Get both source and destination IPs
        src_ip, dst_ip = get_ips_from_request_or_pcap(request, capture_file)

        if email in user_db:
            stored_hash = user_db[email].encode('utf-8')
            if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                login_status = 'Success'
            else:
                login_status = 'Failure'
        else:
            login_status = 'Failure'

        if login_status == 'Failure':
            failed_login_tracker[email] = failed_login_tracker.get(email, 0) + 1
        else:
            failed_login_tracker.setdefault(email, 0)

        save_failed_logins(failed_login_tracker)

        failed_count = failed_login_tracker[email]

        with open(LOG_FILE, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                email, src_ip, dst_ip, timestamp,
                os_name, browser, login_status,
                city, state, country, latitude, longitude, failed_count, capture_file
            ])

        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if email in user_db:
            return "User already exists. Try logging in."

        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user_db[email] = hashed.decode('utf-8')
        save_users(user_db)

        return "Signup successful! You can now login."

    return render_template('signup.html')


if __name__ == '__main__':
    app.run(debug=True)
