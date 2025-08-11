import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from dotenv import load_dotenv
from markupsafe import escape
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
import os
import uuid
import secrets
import functools

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
if not app.secret_key:
    raise RuntimeError("SECRET_KEY environment variable is not set!")

# Upload folder config
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploaded_files')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Admin secret code from env
ADMIN_SECRET_CODE = os.getenv('ADMIN_SECRET_CODE')
if not ADMIN_SECRET_CODE:
    raise RuntimeError("ADMIN_SECRET_CODE environment variable is not set!")

# Email config from env
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),
    SESSION_COOKIE_SECURE=True,      # only over HTTPS; set False if testing on localhost without HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

mail = Mail(app)

# Rate limiter config
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# Email token serializer
s = URLSafeTimedSerializer(app.secret_key)

# Allowed file extensions for upload
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif', 'txt', 'docx'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

DATABASE_PATH = 'database.sqlite3'

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    # Tables consistent in one DB
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
    # Tambah tabel projects
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
    conn.commit()
    conn.close()

init_db()

# --------- CSRF Protection (simple) ---------

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_urlsafe(32)
    return session['_csrf_token']

def verify_csrf_token(token):
    return token == session.get('_csrf_token')

app.jinja_env.globals['csrf_token'] = generate_csrf_token

# --------- Decorators ---------

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

# --------- Helper functions ---------

def get_all_clients():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users_client WHERE verified=1 ORDER BY created_at DESC")
    clients = cur.fetchall()
    conn.close()
    return clients

# --------- Routes ---------

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

        # Check if email already registered
        cur.execute("SELECT 1 FROM users_admin WHERE email = ?", (email,))
        if cur.fetchone():
            flash("Email sudah terdaftar sebagai admin!", "danger")
            conn.close()
            return render_template("register.html")

        cur.execute("SELECT 1 FROM users_client WHERE email = ?", (email,))
        if cur.fetchone():
            flash("Email sudah terdaftar sebagai client!", "danger")
            conn.close()
            return render_template("register.html")

        if admin_code:
            if admin_code != ADMIN_SECRET_CODE:
                flash("Kode rahasia admin salah!", "danger")
                conn.close()
                return render_template("register.html")

            cur.execute(
                "INSERT INTO users_admin (email, token, dashboard_url, verified) VALUES (?, ?, ?, 0)",
                (email, token, dashboard_url)
            )
            conn.commit()
            conn.close()

            verify_link = url_for('verify_email', token=token, _external=True)
            msg = Message('Verifikasi Email Admin Anda', sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = f'Klik link berikut untuk verifikasi akun admin Anda:\n{verify_link}'
            mail.send(msg)

            flash('Link verifikasi admin telah dikirim ke email Anda.', 'success')
            return redirect(url_for('login'))

        else:
            cur.execute(
                "INSERT INTO users_client (email, token, dashboard_url, verified) VALUES (?, ?, ?, 0)",
                (email, token, dashboard_url)
            )
            conn.commit()
            conn.close()

            verify_link = url_for('verify_email', token=token, _external=True)
            msg = Message('Verifikasi Email Anda', sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = f'Klik link berikut untuk verifikasi akun Anda:\n{verify_link}'
            mail.send(msg)

            flash('Link verifikasi telah dikirim ke email Anda.', 'success')
            return redirect(url_for('login'))

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

    cur.execute("SELECT verified FROM users_client WHERE email = ?", (email,))
    user_client = cur.fetchone()
    if user_client:
        if user_client['verified'] == 1:
            flash("Email sudah diverifikasi sebelumnya.", "info")
        else:
            cur.execute("UPDATE users_client SET verified = 1 WHERE email = ?", (email,))
            conn.commit()
            flash("Email berhasil diverifikasi. Silakan login.", "success")
        conn.close()
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
        conn.close()
        return redirect(url_for('login'))

    conn.close()
    flash("User tidak ditemukan.", "danger")
    return redirect(url_for('register'))

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

        cur.execute("SELECT token, verified, dashboard_url FROM users_admin WHERE email = ?", (email,))
        user_admin = cur.fetchone()

        if user_admin:
            token_db, verified, dashboard_url = user_admin['token'], user_admin['verified'], user_admin['dashboard_url']
            if not verified:
                flash("Akun admin belum diverifikasi!", "warning")
                conn.close()
                return render_template("login.html")

            session.clear()
            session['email'] = email
            session['is_admin'] = True
            conn.close()
            return redirect(url_for('admin_dashboard'))

        cur.execute("SELECT token, verified, dashboard_url FROM users_client WHERE email = ?", (email,))
        user_client = cur.fetchone()
        conn.close()

        if user_client:
            token_db, verified, dashboard_url = user_client['token'], user_client['verified'], user_client['dashboard_url']
            if not verified:
                flash("Akun client belum diverifikasi!", "warning")
                return render_template("login.html")

            session.clear()
            session['email'] = email
            session['is_admin'] = False
            # Jangan simpan dashboard_url di session, pakai URL langsung di redirect
            return redirect(url_for('client_dashboard', dashboard_url=dashboard_url))

        flash("Email tidak ditemukan!", "danger")

    return render_template("login.html")

@app.route('/dashboard/<dashboard_url>')
@login_required(is_admin_required=False)
def client_dashboard(dashboard_url):
    email_session = session['email']

    conn = get_db_connection()
    cur = conn.cursor()

    # Cek apakah dashboard_url ada di DB dan cocok dengan email session
    cur.execute("SELECT email FROM users_client WHERE dashboard_url = ?", (dashboard_url,))
    user = cur.fetchone()

    if not user or user['email'] != email_session:
        conn.close()
        flash("Akses tidak valid!", "danger")
        return redirect(url_for('login'))

    # Ambil project + progress client ini
    cur.execute("SELECT project_name, progress FROM projects WHERE user_email = ?", (email_session,))
    projects = cur.fetchall()

    conn.close()

    return render_template("dashboard.html", email=email_session, projects=projects)


@app.route('/admin_dashboard')
@login_required(is_admin_required=True)
def admin_dashboard():
    email_session = session['email']

    conn = get_db_connection()
    conn.row_factory = dict_factory  # <-- Set supaya fetchall menghasilkan dict
    cur = conn.cursor()

    # Cek admin valid
    cur.execute("SELECT email FROM users_admin WHERE email = ?", (email_session,))
    user = cur.fetchone()
    if not user:
        conn.close()
        flash("Akses tidak valid!", "danger")
        return redirect(url_for('login'))

    # Ambil data clients
    cur.execute("SELECT id, email, created_at FROM users_client ORDER BY created_at DESC")
    clients = cur.fetchall()

    cur.execute("SELECT id, email, created_at FROM users_client WHERE status = 'pending' ORDER BY created_at DESC")
    new_clients = cur.fetchall()

    # Ambil semua project dengan progressnya
    cur.execute("""
        SELECT p.id, p.user_email, p.project_name, p.progress
        FROM projects p
        ORDER BY p.user_email, p.project_name
    """)
    projects = cur.fetchall()

    conn.close()

    return render_template("Admin_Dashboard.html", email=email_session, clients=clients, new_clients=new_clients, projects=projects)

@app.route('/delete_client/<int:id>', methods=['POST'])
@login_required(is_admin_required=True)
def delete_client(id):
    csrf_token = request.form.get('csrf_token')
    if not verify_csrf_token(csrf_token):
        abort(403)

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM users_client WHERE id = ?", (id,))
    conn.commit()
    conn.close()

    flash("Client berhasil dihapus.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/approve_client/<int:id>', methods=['POST'])
@login_required(is_admin_required=True)
def approve_client(id):
    csrf_token = request.form.get('csrf_token')
    if not verify_csrf_token(csrf_token):
        abort(403)

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT email FROM users_client WHERE id = ?", (id,))
    data = cur.fetchone()

    if data:
        cur.execute("UPDATE users_client SET status = 'approved' WHERE id = ?", (id,))
        conn.commit()
        flash("Client berhasil disetujui.", "success")
    else:
        flash("Client tidak ditemukan.", "danger")

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

        if not client_id or not any(str(client['id']) == client_id for client in clients):
            flash('Client tidak valid.', 'danger')
            return redirect(url_for('upload_file'))

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)

            client_folder = os.path.join(app.config['UPLOAD_FOLDER'], client_id)
            os.makedirs(client_folder, exist_ok=True)

            file.save(os.path.join(client_folder, filename))
            flash(f'File berhasil diupload untuk client ID: {client_id}', 'success')
            return redirect(url_for('upload_file'))
        else:
            flash('File tidak valid atau ekstensi tidak diizinkan.', 'danger')
            return redirect(url_for('upload_file'))

    # GET method: tampilkan file per client
    files_per_client = {}
    for client in clients:
        folder = os.path.join(app.config['UPLOAD_FOLDER'], str(client['id']))
        if os.path.exists(folder):
            files_per_client[client['email']] = os.listdir(folder)
        else:
            files_per_client[client['email']] = []

    return render_template('dashboard.html', clients=clients, files_per_client=files_per_client)


@app.route('/update_project_progress', methods=['POST'])
@login_required(is_admin_required=True)
def update_project_progress():
    conn = get_db_connection()
    cur = conn.cursor()

    # Ambil semua key dari form yang berisi progress update
    # Format inputnya: progress_<project_id>
    for key, value in request.form.items():
        if key.startswith('progress_'):
            project_id = key.split('_')[1]
            try:
                progress_value = int(value)
                if 0 <= progress_value <= 100:
                    # Update progress di DB
                    cur.execute("UPDATE projects SET progress = ? WHERE id = ?", (progress_value, project_id))
            except ValueError:
                # Abaikan jika bukan angka valid
                pass

    conn.commit()
    conn.close()

    flash("Progress project berhasil diperbarui.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash("Logout berhasil!", "info")
    return redirect(url_for('login'))


if __name__ == '__main__':
    # Jangan debug=True di production, gunakan HTTPS dan proxy jika perlu
    app.run(debug=False, use_reloader=False)



