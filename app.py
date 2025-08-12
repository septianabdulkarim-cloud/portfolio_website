import os
import uuid
import secrets
import functools
import logging
import logging.handlers
import signal
import sys
import threading
from datetime import datetime
import sqlite3
import json
import signal, os, sys

from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, send_file
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from dotenv import load_dotenv
from markupsafe import escape
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from flask import send_from_directory, abort

# ----------------- Load env -----------------
load_dotenv()

# ----------------- Config & paths -----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploaded_files')
LOG_DIR = os.path.join(BASE_DIR, 'logs')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

messages_file = os.path.join(BASE_DIR, 'messages.json')
messages_lock = threading.Lock()

DATABASE_PATH = os.path.join(BASE_DIR, 'database.sqlite3')
LOG_FILE = os.path.join(LOG_DIR, 'app.log')

# ----------------- Logging -----------------
logger = logging.getLogger('app_logger')
logger.setLevel(logging.DEBUG)

# Rotating file handler
file_handler = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=5, encoding='utf-8')
file_formatter = logging.Formatter('%(asctime)s %(levelname)s [%(name)s] %(message)s')
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

# Stream handler (console)
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(file_formatter)
logger.addHandler(stream_handler)

# ----------------- Flask app -----------------
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
if not app.secret_key:
    logger.error("SECRET_KEY environment variable is not set!")
    raise RuntimeError("SECRET_KEY environment variable is not set!")

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

ADMIN_SECRET_CODE = os.getenv('ADMIN_SECRET_CODE')
if not ADMIN_SECRET_CODE:
    logger.error("ADMIN_SECRET_CODE environment variable is not set!")
    raise RuntimeError("ADMIN_SECRET_CODE environment variable is not set!")

# Mail config (optional, will still work without mail but will log failures)
app.config.update(
    MAIL_SERVER=os.getenv('MAIL_SERVER', 'smtp.gmail.com'),
    MAIL_PORT=int(os.getenv('MAIL_PORT', 587)),
    MAIL_USE_TLS=os.getenv('MAIL_USE_TLS', 'True').lower() in ('true', '1', 'yes'),
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),
    SESSION_COOKIE_SECURE=os.getenv('SESSION_COOKIE_SECURE', 'True').lower() in ('true', '1', 'yes'),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

mail = Mail(app)

# Rate limiter
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"]) 

# Token serializer
s = URLSafeTimedSerializer(app.secret_key)

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif', 'txt', 'docx'}

# ----------------- Helpers for DB -----------------

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn



def handle_exit(sig, frame):
    logger.info(f"Received signal {sig}, exiting...")
    sys.stdout.flush()
    os._exit(0)  # langsung hentikan proses tanpa tunggu thread

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
    CREATE TABLE IF NOT EXISTS users_admin (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        token TEXT NOT NULL,
        dashboard_url TEXT NOT NULL,
        verified INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now'))
    );
    ''')
    cur.execute('''
    CREATE TABLE IF NOT EXISTS users_client (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        token TEXT NOT NULL,
        dashboard_url TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        verified INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now'))
    );
    ''')
    cur.execute('''
    CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_email TEXT NOT NULL,
        project_name TEXT NOT NULL,
        progress INTEGER NOT NULL DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(user_email) REFERENCES users_client(email)
    );
    ''')
    cur.execute('''
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_email TEXT NOT NULL,
        project_name TEXT NOT NULL,
        filename TEXT NOT NULL,
        filepath TEXT NOT NULL,
        uploaded_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(user_email) REFERENCES users_client(email)
    );
    ''')
    conn.commit()
    conn.close()

# Initialize DB
init_db()

# ----------------- Messages (JSON) -----------------

def load_messages():
    if not os.path.exists(messages_file):
        with open(messages_file, 'w', encoding='utf-8') as f:
            json.dump([], f)
        return []

    try:
        with open(messages_file, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                return []
            return json.loads(content)
    except (json.JSONDecodeError, IOError) as e:
        logger.exception("Error loading messages: %s", e)
        return []
def save_messages(messages):
    try:
        with open(messages_file, 'w', encoding='utf-8') as f:
            json.dump(messages, f, indent=2, ensure_ascii=False)
    except IOError as e:
        logger.exception("Error saving messages: %s", e)

# ----------------- CSRF -----------------

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_urlsafe(32)
    return session['_csrf_token']


def verify_csrf_token(token):
    return token == session.get('_csrf_token')

app.jinja_env.globals['csrf_token'] = generate_csrf_token

# ----------------- Decorators -----------------

def login_required(is_admin_required=None):
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if 'email' not in session:
                flash("Silakan login terlebih dahulu.", "warning")
                return redirect(url_for('login'))
            if is_admin_required is not None:
                if session.get('is_admin') != is_admin_required:
                    flash("Akses tidak diizinkan.", "danger")
                    return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ----------------- Utility -----------------

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_all_clients():
    conn = get_db_connection()
    conn.row_factory = dict_factory
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users_client WHERE verified=1 ORDER BY created_at DESC")
    clients = cur.fetchall()
    conn.close()
    return clients

# ----------------- Email send (async, daemon thread) -----------------

def _send_email_task(msg_dict):
    try:
        with app.app_context():
            msg = Message(**msg_dict)
            mail.send(msg)
            logger.info("Email sent to %s", msg.recipients)
    except Exception:
        logger.exception("Failed to send email asynchronously")


def send_email_async(msg: Message):
    # Convert Message to serializable dict because flask-mail's Message is not picklable
    msg_dict = {
        'subject': msg.subject,
        'sender': msg.sender,
        'recipients': msg.recipients,
        'body': msg.body,
        'html': getattr(msg, 'html', None)
    }
    t = threading.Thread(target=_send_email_task, args=(msg_dict,), daemon=True)
    t.start()

# ----------------- Routes -----------------

@app.route('/')
def home():
    return render_template("index.html")


@app.route('/about')
def about():
    return render_template("about.html")


@app.route('/projects')
def projects():
    return render_template("projects.html")


@app.route('/contact')
def contact():
    return render_template("contact.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        admin_code = request.form.get('admin_code', '').strip()

        if not email or '@' not in email:
            flash("Email tidak valid!", "danger")
            return render_template("register.html")

        token = s.dumps(email, salt='email-confirm')
        dashboard_url = str(uuid.uuid4())

        conn = get_db_connection()
        cur = conn.cursor()

        try:
            # Check existing
            cur.execute("SELECT 1 FROM users_admin WHERE email = ?", (email,))
            if cur.fetchone():
                flash("Email sudah terdaftar sebagai admin!", "danger")
                return render_template("register.html")

            cur.execute("SELECT 1 FROM users_client WHERE email = ?", (email,))
            if cur.fetchone():
                flash("Email sudah terdaftar sebagai client!", "danger")
                return render_template("register.html")

            if admin_code:
                if admin_code != ADMIN_SECRET_CODE:
                    flash("Kode rahasia admin salah!", "danger")
                    return render_template("register.html")

                cur.execute(
                    "INSERT INTO users_admin (email, token, dashboard_url, verified) VALUES (?, ?, ?, 0)",
                    (email, token, dashboard_url)
                )
                conn.commit()

                verify_link = url_for('verify_email', token=token, _external=True)
                msg = Message('Verifikasi Email Admin Anda', sender=app.config.get('MAIL_USERNAME'), recipients=[email])
                msg.body = f'Klik link berikut untuk verifikasi akun admin Anda:\n{verify_link}'
                try:
                    send_email_async(msg)
                except Exception:
                    logger.exception("Gagal mengirim email verifikasi admin (async)")

                flash('Link verifikasi admin telah dikirim ke email Anda.', 'success')
                return redirect(url_for('login'))

            else:
                cur.execute(
                    "INSERT INTO users_client (email, token, dashboard_url, verified) VALUES (?, ?, ?, 0)",
                    (email, token, dashboard_url)
                )
                conn.commit()

                verify_link = url_for('verify_email', token=token, _external=True)
                msg = Message('Verifikasi Email Anda', sender=app.config.get('MAIL_USERNAME'), recipients=[email])
                msg.body = f'Klik link berikut untuk verifikasi akun Anda:\n{verify_link}'
                try:
                    send_email_async(msg)
                except Exception:
                    logger.exception("Gagal mengirim email verifikasi client (async)")

                flash('Link verifikasi telah dikirim ke email Anda.', 'success')
                return redirect(url_for('login'))
        finally:
            conn.close()

    return render_template("register.html")


@app.route('/verify/<token>')
def verify_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except SignatureExpired:
        flash('Link verifikasi sudah kadaluarsa.', 'danger')
        return redirect(url_for('register'))
    except BadSignature:
        flash('Token verifikasi tidak valid.', 'danger')
        return redirect(url_for('register'))

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        cur.execute("SELECT verified FROM users_client WHERE email = ?", (email,))
        user_client = cur.fetchone()
        if user_client:
            if user_client['verified'] == 1:
                flash("Email sudah diverifikasi sebelumnya.", "info")
            else:
                cur.execute("UPDATE users_client SET verified = 1 WHERE email = ?", (email,))
                conn.commit()
                flash("Email berhasil diverifikasi. Silakan login.", "success")
            return redirect(url_for('login'))

        cur.execute("SELECT verified FROM users_admin WHERE email = ?", (email,))
        user_admin = cur.fetchone()
        if user_admin:
            if user_admin['verified'] == 1:
                flash("Email sudah diverifikasi sebelumnya.", "info")
            else:
                cur.execute("UPDATE users_admin SET verified = 1 WHERE email = ?", (email,))
                conn.commit()
                flash("Email berhasil diverifikasi. Silakan login.", "success")
            return redirect(url_for('login'))

        flash("User tidak ditemukan.", "danger")
        return redirect(url_for('register'))
    finally:
        conn.close()


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", error_message="Terlalu banyak percobaan login. Coba lagi nanti.")
def login():
    if request.method == 'POST':
        email = escape(request.form.get('email', '').strip().lower())
        if not email or '@' not in email:
            flash("Format email tidak valid!", "danger")
            return render_template("login.html")

        conn = get_db_connection()
        cur = conn.cursor()

        try:
            cur.execute("SELECT token, verified, dashboard_url FROM users_admin WHERE email = ?", (email,))
            user_admin = cur.fetchone()

            if user_admin:
                token_db, verified, dashboard_url = user_admin['token'], user_admin['verified'], user_admin['dashboard_url']
                if not verified:
                    flash("Akun admin belum diverifikasi!", "warning")
                    return render_template("login.html")

                session.clear()
                session['email'] = email
                session['is_admin'] = True
                return redirect(url_for('admin_dashboard'))

            cur.execute("SELECT token, verified, dashboard_url FROM users_client WHERE email = ?", (email,))
            user_client = cur.fetchone()

            if user_client:
                token_db, verified, dashboard_url = user_client['token'], user_client['verified'], user_client['dashboard_url']
                if not verified:
                    flash("Akun client belum diverifikasi!", "warning")
                    return render_template("login.html")

                session.clear()
                session['email'] = email
                session['is_admin'] = False
                return redirect(url_for('client_dashboard', dashboard_url=dashboard_url))

            flash("Email tidak ditemukan!", "danger")
        finally:
            conn.close()

    return render_template("login.html")


@app.route('/dashboard/<dashboard_url>', methods=['GET'])
@login_required(is_admin_required=False)
def client_dashboard(dashboard_url):
    email_session = session['email']

    conn = get_db_connection()
    conn.row_factory = dict_factory
    cur = conn.cursor()

    try:
        cur.execute("SELECT email FROM users_client WHERE dashboard_url = ?", (dashboard_url,))
        user = cur.fetchone()
        if not user or user['email'] != email_session:
            flash("Akses tidak valid!", "danger")
            return redirect(url_for('login'))

        cur.execute("SELECT project_name, progress FROM projects WHERE user_email = ?", (email_session,))
        projects = cur.fetchall()

        cur.execute("SELECT project_name, filename, uploaded_at FROM files WHERE user_email = ? ORDER BY uploaded_at DESC", (email_session,))
        files_raw = cur.fetchall()

        files_per_project = {}
        for row in files_raw:
            project = row['project_name']
            files_per_project.setdefault(project, []).append({
                'filename': row['filename'],
                'uploaded_at': row['uploaded_at']
            })

        # Jika memang kamu tidak ada data clients untuk client dashboard, 
        # kirim list kosong supaya tidak error di template
        clients = []  
        files_per_client = {}  # definisikan juga supaya tidak error json

        messages = load_messages()
        messages_client = [m for m in messages if m.get('sender_email') == email_session or m.get('receiver_email') == email_session]

        return render_template(
            "dashboard.html",
            user=user,
            dashboard_url=dashboard_url,
            messages=messages_client,
            clients=clients,
            projects=projects or [],
            files_per_client=files_per_client,
            files_per_project=files_per_project or {},
            email=email_session  # wajib kirim ini supaya template tidak error
        )
    finally:
        conn.close()


@app.route('/admin_dashboard', methods=['GET', 'POST'])
@login_required(is_admin_required=True)
def admin_dashboard():
    email_session = session['email']

    if request.method == 'POST':
        # Proses upload file
        if 'file' not in request.files:
            flash('Tidak ada file yang dipilih', 'danger')
            return redirect(url_for('admin_dashboard'))

        file = request.files['file']
        if file.filename == '':
            flash('Nama file kosong', 'danger')
            return redirect(url_for('admin_dashboard'))

        client_id = request.form.get('client_id')
        project_name = request.form.get('project_name')

        if not client_id or not project_name:
            flash('Client dan project harus dipilih', 'danger')
            return redirect(url_for('admin_dashboard'))

        filename = secure_filename(file.filename)

        client_folder = os.path.join(app.config['UPLOAD_FOLDER'], client_id)
        os.makedirs(client_folder, exist_ok=True)

        save_path = os.path.join(client_folder, filename)
        file.save(save_path)

        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("SELECT email FROM users_client WHERE id = ?", (client_id,))
            client = cur.fetchone()
            if not client:
                flash('Client tidak ditemukan', 'danger')
                return redirect(url_for('admin_dashboard'))

            user_email = client['email']
            now = datetime.now().isoformat(timespec='seconds')

            cur.execute("""
                INSERT INTO files (user_email, project_name, filename, filepath, uploaded_at)
                VALUES (?, ?, ?, ?, ?)
            """, (user_email, project_name, filename, save_path, now))
            conn.commit()

            flash('File berhasil diupload', 'success')
            return redirect(url_for('admin_dashboard'))
        finally:
            conn.close()

    # GET request: tampilkan dashboard admin
    conn = get_db_connection()
    conn.row_factory = dict_factory
    cur = conn.cursor()

    try:
        # Validasi admin
        cur.execute("SELECT email FROM users_admin WHERE email = ?", (email_session,))
        user = cur.fetchone()
        if not user:
            flash("Akses tidak valid!", "danger")
            return redirect(url_for('login'))

        # Ambil data clients
        cur.execute("SELECT id, email, created_at FROM users_client ORDER BY created_at DESC")
        clients = cur.fetchall()

        # Ambil data project
        cur.execute("SELECT id, user_email, project_name, progress FROM projects ORDER BY user_email, project_name")
        projects = cur.fetchall()

        # Ambil file
        cur.execute("SELECT id, user_email, project_name, filename, filepath, uploaded_at FROM files ORDER BY uploaded_at DESC")
        files = cur.fetchall()

        # Ambil pesan dari file JSON (tanpa DB)
        messages = load_messages()

        return render_template(
            "Admin_Dashboard.html",
            email=email_session,
            clients=clients,
            projects=projects,
            files=files,
            messages=messages
        )
    finally:
        conn.close()


@app.route('/update_project_progress', methods=['POST'])
@login_required(is_admin_required=True)
def update_project_progress():
    conn = get_db_connection()
    cur = conn.cursor()

    try:
        for key, value in request.form.items():
            if key.startswith('progress_'):
                project_id = key.split('_', 1)[1]
                try:
                    progress_value = int(value)
                    if 0 <= progress_value <= 100:
                        cur.execute("UPDATE projects SET progress = ? WHERE id = ?", (progress_value, project_id))
                except ValueError:
                    pass

        conn.commit()
        flash("Progress project berhasil diperbarui.", "success")
    finally:
        conn.close()

    return redirect(url_for('admin_dashboard'))


@app.route('/delete_client/<int:id>', methods=['POST'])
@login_required(is_admin_required=True)
def delete_client(id):
    csrf_token = request.form.get('csrf_token')
    if not verify_csrf_token(csrf_token):
        abort(403)

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM users_client WHERE id = ?", (id,))
        conn.commit()
        flash("Client berhasil dihapus.", "success")
    finally:
        conn.close()

    return redirect(url_for('admin_dashboard'))


@app.route('/approve_client/<int:id>', methods=['POST'])
@login_required(is_admin_required=True)
def approve_client(id):
    csrf_token = request.form.get('csrf_token')
    if not verify_csrf_token(csrf_token):
        abort(403)

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        cur.execute("SELECT email FROM users_client WHERE id = ?", (id,))
        data = cur.fetchone()

        if data:
            cur.execute("UPDATE users_client SET status = 'approved' WHERE id = ?", (id,))
            conn.commit()
            flash("Client berhasil disetujui.", "success")
        else:
            flash("Client tidak ditemukan.", "danger")
    finally:
        conn.close()

    return redirect(url_for('admin_dashboard'))


@app.route('/upload', methods=['GET', 'POST'])
@login_required(is_admin_required=True)
def upload_file():
    clients = get_all_clients()

    if request.method == 'POST':
        csrf_token = request.form.get('csrf_token')
        if not verify_csrf_token(csrf_token):
            abort(403)

        file = request.files.get('file')
        client_id = request.form.get('client_id')
        project_name = request.form.get('project_name', '').strip()

        if not client_id or not any(str(client['id']) == client_id for client in clients):
            flash('Client tidak valid.', 'danger')
            return redirect(url_for('upload_file'))

        if not project_name:
            flash('Project harus diisi.', 'danger')
            return redirect(url_for('upload_file'))

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)

            # Simpan file ke folder per client_id
            client_folder = os.path.join(app.config['UPLOAD_FOLDER'], client_id)
            os.makedirs(client_folder, exist_ok=True)

            save_path = os.path.join(client_folder, filename)
            file.save(save_path)

            # Simpan metadata file ke DB
            conn = get_db_connection()
            cur = conn.cursor()
            try:
                cur.execute("SELECT email FROM users_client WHERE id = ?", (client_id,))
                client = cur.fetchone()
                if not client:
                    flash('Client tidak ditemukan.', 'danger')
                    return redirect(url_for('upload_file'))

                user_email = client['email']
                now = datetime.now().isoformat(timespec='seconds')

                cur.execute("""
                    INSERT INTO files (user_email, project_name, filename, filepath, uploaded_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (user_email, project_name, filename, save_path, now))
                conn.commit()

                flash(f'File berhasil diupload untuk client {user_email}', 'success')
                return redirect(url_for('upload_file'))
            finally:
                conn.close()
        else:
            flash('File tidak valid atau ekstensi tidak diizinkan.', 'danger')
            return redirect(url_for('upload_file'))

    # GET: tampilkan halaman upload dengan daftar client dan file per client
    files_per_client = {}
    for client in clients:
        folder = os.path.join(app.config['UPLOAD_FOLDER'], str(client['id']))
        if os.path.exists(folder):
            files_per_client[client['email']] = os.listdir(folder)
        else:
            files_per_client[client['email']] = []

    return render_template(
        'upload.html',
        clients=clients,
        files_per_client=files_per_client,
        csrf_token=generate_csrf_token()
    )



@app.route('/send_admin_message', methods=['POST'])
@login_required(is_admin_required=True)
def send_admin_message():
    sender_email = session['email']
    client_email = request.form.get('receiver_email')  # Email user tujuan

    message_text = request.form.get('message')

    if not message_text or not client_email:
        flash('Pesan dan email penerima harus diisi', 'danger')
        return redirect(request.referrer or url_for('admin_dashboard'))

    new_message = {
        'sender_email': sender_email,
        'receiver_email': client_email,
        'message': message_text,
        'sent_at': datetime.now().isoformat(timespec='seconds')
    }

    with messages_lock:
        messages = load_messages()
        messages.append(new_message)
        save_messages(messages)

    logger.info("New admin message from %s to %s", sender_email, client_email)

    flash('Pesan berhasil dikirim ke user', 'success')
    return redirect(request.referrer or url_for('admin_dashboard'))


@app.route('/send_client_message', methods=['POST'])
@login_required(is_admin_required=False)
def send_client_message():
    sender_email = session['email']
    admin_email = os.getenv('ADMIN_CONTACT_EMAIL', 'admin@example.com')

    message_text = request.form.get('message')

    if not message_text:
        flash('Pesan harus diisi', 'danger')
        return redirect(request.referrer or url_for('client_dashboard', dashboard_url=''))

    new_message = {
        'sender_email': sender_email,
        'receiver_email': admin_email,
        'message': message_text,
        'sent_at': datetime.now().isoformat(timespec='seconds')
    }

    with messages_lock:
        messages = load_messages()
        messages.append(new_message)
        save_messages(messages)

    logger.info("New client message from %s to %s", sender_email, admin_email)

    flash('Pesan berhasil dikirim', 'success')
    return redirect(request.referrer or url_for('client_dashboard', dashboard_url=''))



@app.route('/download/<path:filename>')
@login_required(is_admin_required=False)
def download_file(filename):
    upload_folder = os.path.join(app.root_path, 'uploads')  # folder penyimpanan file
    file_path = os.path.join(upload_folder, filename)

    if not os.path.isfile(file_path):
        abort(404)  # Kalau tidak ada, balikin error

    return send_from_directory(upload_folder, filename, as_attachment=True)

@app.route('/logout')
def logout():
    session.clear()
    flash("Logout berhasil!", "info")
    return redirect(url_for('login'))


@app.route('/logs')
@login_required(is_admin_required=True)
def view_logs():
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            content = f.read()
        # renders a simple template that shows logs in a <pre>
        return render_template('logs.html', logs=content)
    except Exception:
        logger.exception("Gagal membaca file log")
        flash('Gagal membaca file log', 'danger')
        return redirect(url_for('admin_dashboard'))


@app.route('/shutdown', methods=['POST'])
@login_required(is_admin_required=True)
def shutdown():
    csrf_token = request.form.get('csrf_token')
    if not verify_csrf_token(csrf_token):
        abort(403)

    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        logger.error("Not running with the Werkzeug Server")
        flash('Tidak dapat mematikan server secara otomatis di environment ini.', 'danger')
        return redirect(url_for('admin_dashboard'))

    logger.info("Shutdown requested by admin %s", session.get('email'))
    func()
    return 'Shutting down...'

# ----------------- Signal handling (graceful) -----------------

def _handle_exit(signum, frame):
    logger.info('Received signal %s, exiting...', signum)
    # let Python exit normally; threads that are daemon will not block
    sys.exit(0)

signal.signal(signal.SIGINT, _handle_exit)
signal.signal(signal.SIGTERM, _handle_exit)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
# ----------------- Run -----------------

