from flask import Blueprint, render_template, request, session, redirect, url_for, flash, jsonify
import csv, json, os
from datetime import datetime
from functools import wraps
import os

admin_bp = Blueprint('admin', __name__)

ADMIN_CRED_FILE    = 'admin.json'
LOGIN_LOG_FILE     = 'cyber1_scored.csv'
BANNED_FILE        = 'banned_users.json'
BLOOM_BLOCKED_FILE = 'bloom_blocked.json'
ADMIN_AUDIT_LOG    = 'admin_audit.log'
PAGERANK_FILE      = 'pagerank_scores.csv'

# Ensure banned file exists
for path, default in [(BANNED_FILE, []), (BLOOM_BLOCKED_FILE, [])]:
    if not os.path.exists(path):
        with open(path, 'w') as f:
            json.dump(default, f)

# Load pagerank scores into dict
pagerank_dict = {}
if os.path.exists(PAGERANK_FILE):
    with open(PAGERANK_FILE, 'r') as pf:
        reader = csv.DictReader(pf)
        for row in reader:
            try:
                pagerank_dict[row['Node']] = float(row['PageRank'])
            except Exception:
                pagerank_dict[row['Node']] = 0.0


def load_admin_creds():
    if os.path.exists(ADMIN_CRED_FILE):
        with open(ADMIN_CRED_FILE) as f:
            return json.load(f)
    return {}


def load_banned_users():
    with open(BANNED_FILE) as f:
        return json.load(f)
    
def load_bloom_blocked():
    with open(BLOOM_BLOCKED_FILE) as f:
        return json.load(f)


def save_banned_users(users):
    with open(BANNED_FILE, 'w') as f:
        json.dump(users, f)


def log_admin_action(action, username=None):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"{ts} | {action}"
    if username:
        entry += f" | User: {username}"
    with open(ADMIN_AUDIT_LOG, 'a') as f:
        f.write(entry + "\n")


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('admin'):
            return redirect(url_for('admin.admin_login'))
        return f(*args, **kwargs)
    return wrapper

@admin_bp.route('/admin', methods=['GET','POST'])
def admin_login():
    if request.method == 'POST':
        uname = request.form.get('admin_username')
        pwd   = request.form.get('admin_password')
        creds = load_admin_creds()
        # For secure storage, store hashed admin password
        if creds.get('username') == uname and creds.get('password') == pwd:
            session['admin'] = True
            flash('✅ Welcome Admin!', 'success')
            log_admin_action("Admin logged in")
            return redirect(url_for('admin.admin_dashboard'))
        flash('❌ Invalid admin credentials', 'danger')
    return render_template('admin_login.html')

@admin_bp.route('/admin/logout')
@admin_required
def admin_logout():
    session.pop('admin', None)
    flash('🔒 Logged out successfully.', 'info')
    log_admin_action("Admin logged out")
    return redirect(url_for('admin.admin_login'))

@admin_bp.route('/admin/dashboard', methods=['GET','POST'])
@admin_required
def admin_dashboard():
    explicit = load_banned_users()
    bloom = load_bloom_blocked()
    all_blocked = sorted(set(explicit + bloom))

    search_results = []
    banned_users = bloom
    username = None

    if request.method == 'POST':
        username = request.form.get('search_username')
        if username:
            with open(LOGIN_LOG_FILE, 'r') as f:
                raw_reader = csv.reader(f)
                headers = next(raw_reader)

                # Make headers unique
                seen = {}
                for i, h in enumerate(headers):
                    if h in seen:
                        seen[h] += 1
                        headers[i] = f"{h}_{seen[h]}"
                    else:
                        seen[h] = 1

                f.seek(0)
                next(f)  # Skip original header
                reader = csv.DictReader(f, fieldnames=headers)

                for row in reader:
                    if row['Username'] == username:
                        pr = pagerank_dict.get(username, 0.0)
                        row['pagerank'] = pr

                        try:
                            lat = float(row.get('Latitude', '0'))
                            lon = float(row.get('Longitude', '0'))
                            row['Latitude'] = lat
                            row['Longitude'] = lon
                        except Exception:
                            row['Latitude'] = None
                            row['Longitude'] = None

                        search_results.append(row)

    # Normalize and sort logs
    for row in search_results:
        try:
            val = row.get('Failed Login Count', '0')
            row['Failed Login Count'] = int(float(val.strip()))
        except Exception:
            row['Failed Login Count'] = 0

    try:
        search_results.sort(
            key=lambda r: datetime.strptime(r['Timestamp'], "%Y-%m-%d %H:%M:%S")
        )
    except Exception:
        pass

    raw = search_results[-1]['Failed Login Count'] if search_results else 'N/A'

    return render_template(
        'admin_dashboard.html',
        logs=search_results if username else [],
        banned=banned_users,
        username=username,
        pagerank_dict=pagerank_dict,
        latest_failure=raw
    )


@admin_bp.route('/admin/ban/<username>', methods=['POST'])
@admin_required
def ban_user(username):
    # 1️⃣ Load & update your manual bans
    banned = load_banned_users()
    if username not in banned:
        banned.append(username)
        save_banned_users(banned)
        flash(f'🚫 {username} has been banned.', 'warning')
        log_admin_action("User banned", username)

    # 2️⃣ ALSO add them to your Bloom-blocked list for enumeration
    bloom = load_bloom_blocked()
    if username not in bloom:
        bloom.append(username)
        # inline save without a helper
        with open(BLOOM_BLOCKED_FILE, 'w') as f:
            json.dump(bloom, f)

    return redirect(url_for('admin.admin_dashboard'))

@admin_bp.route('/admin/unban/<username>', methods=['POST'])
@admin_required
def unban_user(username):
    banned = load_banned_users()
    if username in banned:
        banned.remove(username)
        save_banned_users(banned)
        flash(f'✅ {username} has been unbanned.', 'success')
        log_admin_action("User unbanned", username)
        
    bloom = load_bloom_blocked()
    if username in bloom:
        bloom.remove(username)
        with open(BLOOM_BLOCKED_FILE, 'w') as f:
            json.dump(bloom, f)
    return redirect(url_for('admin.admin_dashboard'))

@admin_bp.route('/admin/api/user_logins/<username>')
@admin_required
def user_logins_api(username):
    logs = []
    with open(LOGIN_LOG_FILE, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['Username'] == username:
                pr = pagerank_dict.get(username, 0.0)
                row['pagerank'] = pr
                logs.append(row)
    return jsonify(logs)
