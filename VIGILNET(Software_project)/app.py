from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify 
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, UserHistory
from functools import wraps
from datetime import timedelta, datetime
from modules.packet_sniffer import get_packet_stats
from modules.vulnerability import scan_vulnerability
from modules.encryption import encrypt_data, decrypt_data
from modules.phishing import check_phishing_url
from modules.hashing import generate_hash

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = 'your_very_strong_secret_key_here'
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Configure and initialize the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vigilnet.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# Create the database tables if they don't exist
with app.app_context():
    db.create_all()

def log_action(username, action):
    user = User.query.filter_by(username=username).first()
    if user:
        history = UserHistory(user_id=user.id, action=action, timestamp=datetime.utcnow())
        db.session.add(history)
        db.session.commit()

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        flash('Please log in first')
        return redirect(url_for('login'))
    return wrap

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['logged_in'] = True
            session['username'] = username
            log_action(username, 'Logged in')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose another.')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    log_action(session['username'], 'Visited dashboard')
    return render_template('dashboard.html')

@app.route('/traffic')
@login_required
def traffic():
    log_action(session['username'], 'Viewed traffic')
    return render_template('traffic.html')

@app.route('/traffic/data')
@login_required
def traffic_data():
    stats = get_packet_stats()
    return jsonify(stats)

@app.route('/api/suspicious-packets')
@login_required
def get_suspicious_packets():
    data = get_packet_stats()
    return jsonify(data.get('suspicious', []))

@app.route('/api/packet-connections')
@login_required
def get_packet_connections():
    data = get_packet_stats()
    return jsonify(data)

@app.route('/vulnerability')
@login_required
def vulnerability():
    return render_template('vulnerability.html')

@app.route('/vulnerability/scan', methods=['POST'])
@login_required
def vulnerability_scan():
    target = request.form.get('target')
    results = scan_vulnerability(target)
    log_action(session['username'], f'Scanned vulnerability on {target}')
    return jsonify(results)

@app.route('/encryption')
@login_required
def encryption():
    return render_template('encryption.html')

@app.route('/encryption/process', methods=['POST'])
@login_required
def encryption_process():
    action = request.form.get('action')
    text = request.form.get('text')
    key = request.form.get('key')

    if action == 'encrypt':
        result = encrypt_data(text, key)
        log_action(session['username'], 'Performed encryption')
    else:
        result = decrypt_data(text, key)
        log_action(session['username'], 'Performed decryption')

    return jsonify({'result': result})

@app.route('/phishing')
@login_required
def phishing():
    return render_template('phishing.html')

@app.route('/phishing/check', methods=['POST'])
@login_required
def phishing_check():
    url = request.form.get('url')
    result = check_phishing_url(url)
    log_action(session['username'], f'Checked phishing URL: {url}')
    return jsonify(result)

@app.route('/hashing')
@login_required
def hashing():
    return render_template('hashing.html')

@app.route('/hashing/generate', methods=['POST'])
@login_required
def hashing_generate():
    text = request.form.get('text')
    algorithm = request.form.get('algorithm')
    result = generate_hash(text, algorithm)
    log_action(session['username'], f'Generated hash with {algorithm}')
    return jsonify({'hash': result})

@app.route('/history')
@login_required
def user_history():
    user = User.query.filter_by(username=session['username']).first()
    two_days_ago = datetime.utcnow() - timedelta(days=2)
    history = UserHistory.query.filter(
        UserHistory.user_id == user.id,
        UserHistory.timestamp >= two_days_ago
    ).order_by(UserHistory.timestamp.desc()).all()
    return render_template('history.html', history=history)

@app.route('/logout')
def logout():
    log_action(session.get('username', 'unknown'), 'Logged out')
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
