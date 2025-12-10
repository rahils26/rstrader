"""
RS Trader - Authentication Server
Handles email + IP based login restrictions
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import os
import hashlib
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)

# Data file paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(BASE_DIR, 'data', 'authorized_users.json')
SESSIONS_FILE = os.path.join(BASE_DIR, 'data', 'active_sessions.json')

# Session timeout (hours)
SESSION_TIMEOUT = 24

def load_json(filepath):
    """Load JSON file or return empty dict"""
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            return json.load(f)
    return {}

def save_json(filepath, data):
    """Save data to JSON file"""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)

def get_client_ip():
    """Get real client IP (handles proxies)"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    return request.remote_addr

def generate_token(email, ip):
    """Generate session token"""
    data = f"{email}{ip}{datetime.now().isoformat()}"
    return hashlib.sha256(data.encode()).hexdigest()[:32]

def cleanup_expired_sessions():
    """Remove expired sessions"""
    sessions = load_json(SESSIONS_FILE)
    current_time = datetime.now()
    updated = {}

    for email, session in sessions.items():
        session_time = datetime.fromisoformat(session.get('timestamp', '2000-01-01'))
        if current_time - session_time < timedelta(hours=SESSION_TIMEOUT):
            updated[email] = session

    if len(updated) != len(sessions):
        save_json(SESSIONS_FILE, updated)

    return updated

@app.route('/api/auth/login', methods=['POST'])
def login():
    """
    Login endpoint
    - Checks if email is authorized
    - Checks if email is already logged in from different IP
    - Creates new session if valid
    """
    data = request.json
    email = data.get('email', '').lower().strip()

    if not email:
        return jsonify({'success': False, 'error': 'Email is required'}), 400

    client_ip = get_client_ip()

    # Load authorized users
    users = load_json(USERS_FILE)

    # Check if email is authorized
    if email not in users.get('authorized_emails', []):
        return jsonify({
            'success': False,
            'error': 'This email is not authorized. Contact admin.'
        }), 403

    # Clean up expired sessions
    sessions = cleanup_expired_sessions()

    # Check if already logged in from different IP
    if email in sessions:
        existing_ip = sessions[email].get('ip')
        if existing_ip and existing_ip != client_ip:
            return jsonify({
                'success': False,
                'error': f'Already logged in from another device ({existing_ip[:8]}...). Logout first or wait {SESSION_TIMEOUT}h.'
            }), 403

    # Create new session
    token = generate_token(email, client_ip)
    sessions[email] = {
        'ip': client_ip,
        'token': token,
        'timestamp': datetime.now().isoformat(),
        'login_count': sessions.get(email, {}).get('login_count', 0) + 1
    }
    save_json(SESSIONS_FILE, sessions)

    return jsonify({
        'success': True,
        'token': token,
        'email': email,
        'ip': client_ip,
        'message': 'Login successful'
    })

@app.route('/api/auth/verify', methods=['POST'])
def verify():
    """Verify if session is still valid"""
    data = request.json
    email = data.get('email', '').lower().strip()
    token = data.get('token', '')

    if not email or not token:
        return jsonify({'valid': False, 'error': 'Missing credentials'}), 400

    client_ip = get_client_ip()
    sessions = cleanup_expired_sessions()

    if email not in sessions:
        return jsonify({'valid': False, 'error': 'Session expired'}), 401

    session = sessions[email]

    # Verify token and IP
    if session.get('token') != token:
        return jsonify({'valid': False, 'error': 'Invalid token'}), 401

    if session.get('ip') != client_ip:
        return jsonify({'valid': False, 'error': 'IP mismatch'}), 401

    return jsonify({'valid': True, 'email': email})

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """Logout and clear session"""
    data = request.json
    email = data.get('email', '').lower().strip()
    token = data.get('token', '')

    sessions = load_json(SESSIONS_FILE)

    if email in sessions:
        if sessions[email].get('token') == token:
            del sessions[email]
            save_json(SESSIONS_FILE, sessions)
            return jsonify({'success': True, 'message': 'Logged out successfully'})

    return jsonify({'success': False, 'error': 'Session not found'}), 404

@app.route('/api/admin/add-user', methods=['POST'])
def add_user():
    """Add authorized email (admin only - protect this in production!)"""
    data = request.json
    admin_key = data.get('admin_key', '')
    email = data.get('email', '').lower().strip()

    # Simple admin key check (change this in production!)
    if admin_key != 'rs-trader-admin-2024':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    if not email:
        return jsonify({'success': False, 'error': 'Email required'}), 400

    users = load_json(USERS_FILE)
    if 'authorized_emails' not in users:
        users['authorized_emails'] = []

    if email not in users['authorized_emails']:
        users['authorized_emails'].append(email)
        save_json(USERS_FILE, users)
        return jsonify({'success': True, 'message': f'Added {email}'})

    return jsonify({'success': False, 'error': 'Email already exists'})

@app.route('/api/admin/remove-user', methods=['POST'])
def remove_user():
    """Remove authorized email"""
    data = request.json
    admin_key = data.get('admin_key', '')
    email = data.get('email', '').lower().strip()

    if admin_key != 'rs-trader-admin-2024':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    users = load_json(USERS_FILE)
    if email in users.get('authorized_emails', []):
        users['authorized_emails'].remove(email)
        save_json(USERS_FILE, users)

        # Also remove active session
        sessions = load_json(SESSIONS_FILE)
        if email in sessions:
            del sessions[email]
            save_json(SESSIONS_FILE, sessions)

        return jsonify({'success': True, 'message': f'Removed {email}'})

    return jsonify({'success': False, 'error': 'Email not found'})

@app.route('/api/admin/list-users', methods=['POST'])
def list_users():
    """List all authorized users and active sessions"""
    data = request.json
    admin_key = data.get('admin_key', '')

    if admin_key != 'rs-trader-admin-2024':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    users = load_json(USERS_FILE)
    sessions = cleanup_expired_sessions()

    return jsonify({
        'success': True,
        'authorized_emails': users.get('authorized_emails', []),
        'active_sessions': {
            email: {
                'ip': s['ip'][:12] + '...',
                'login_time': s['timestamp']
            } for email, s in sessions.items()
        }
    })

@app.route('/api/admin/force-logout', methods=['POST'])
def force_logout():
    """Force logout a user (admin)"""
    data = request.json
    admin_key = data.get('admin_key', '')
    email = data.get('email', '').lower().strip()

    if admin_key != 'rs-trader-admin-2024':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    sessions = load_json(SESSIONS_FILE)
    if email in sessions:
        del sessions[email]
        save_json(SESSIONS_FILE, sessions)
        return jsonify({'success': True, 'message': f'Force logged out {email}'})

    return jsonify({'success': False, 'error': 'No active session for this email'})

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'ok', 'service': 'RS Trader Auth'})

if __name__ == '__main__':
    # Create initial data files if they don't exist
    if not os.path.exists(USERS_FILE):
        save_json(USERS_FILE, {
            'authorized_emails': [
                'ashwinsahu777@gmail.com',
                'rstest2607@gmail.com'
            ]
        })
        print(f"Created {USERS_FILE} with default users")

    if not os.path.exists(SESSIONS_FILE):
        save_json(SESSIONS_FILE, {})

    print("=" * 50)
    print("  RS Trader Authentication Server")
    print("  Running on http://localhost:5002")
    print("=" * 50)

    app.run(host='0.0.0.0', port=5002, debug=True)
