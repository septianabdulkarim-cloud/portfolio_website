from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from database.db import get_db_connection, init_db
from dotenv import load_dotenv
from flask import send_from_directory
from markupsafe import escape
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import flash, redirect, url_for
from itsdangerous import SignatureExpired, BadSignature
import os, uuid, logging
import secrets



# Load .env
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')


limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# Logging
if not os.path.exists("logs"):
    os.makedirs("logs")
logging.basicConfig(filename='logs/app.log', level=logging.INFO,
                    format='%(asctime)s %(levelname)s: %(message)s')

# Email config
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
mail = Mail(app)

# Token generator
s = URLSafeTimedSerializer(app.secret_key)

# Init DB
init_db()

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
        email = request.form['email']
        token = s.dumps(email, salt='email-confirm')
        dashboard_url = str(uuid.uuid4())

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = ?", (email,))
        exists = cur.fetchone()
        if exists:
            flash("Email sudah terdaftar!", "danger")
            return render_template("register.html")

        cur.execute("INSERT INTO users (email, token, dashboard_url) VALUES (?, ?, ?)",
                    (email, token, dashboard_url))
        conn.commit()
        conn.close()

        verify_link = url_for('verify_email', token=token, _external=True)
        msg = Message('Verifikasi Email Anda', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f'Klik link berikut untuk verifikasi akun Anda:\n{verify_link}'
        mail.send(msg)

        flash('Link verifikasi telah dikirim ke email Anda.', 'success')
        logging.info(f"Register: {email}")
        return redirect(url_for('login'))
    return render_template("register.html")

@app.route('/verify/<token>')
def verify_email(token):
    try:
        # Coba decode token
        email = s.loads(token, salt='email-confirm', max_age=3600)  # 1 jam berlaku
    except SignatureExpired:
        flash('Link verifikasi sudah kadaluarsa.', 'danger')
        return redirect(url_for('register'))
    except BadSignature:
        flash('Token verifikasi tidak valid.', 'danger')
        return redirect(url_for('register'))

    # Update status verifikasi user di database
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cur.fetchone()

    if not user:
        flash("User tidak ditemukan.", "danger")
        return redirect(url_for('register'))

    if user['verified'] == 1:
        flash("Email Anda sudah diverifikasi sebelumnya.", "info")
    else:
        cur.execute("UPDATE users SET verified = 1 WHERE email = ?", (email,))
        conn.commit()
        flash("Email berhasil diverifikasi. Silakan login.", "success")

    conn.close()
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", error_message="Terlalu banyak percobaan login. Coba lagi nanti.")
def login():
    if request.method == 'POST':
        email = escape(request.form['email'].strip().lower())

        if not email or '@' not in email:
            flash("Format email tidak valid!", "danger")
            return render_template("login.html")

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT token, is_verified, is_admin, dashboard_url FROM users WHERE email = ?", (email,))
        user = cur.fetchone()
        conn.close()

        if user:
            token_db, verified, is_admin, dashboard_url = user

            if not verified:
                flash("Akun belum diverifikasi!", "warning")
                return render_template("login.html")

            # Simpan ke session
            session['email'] = email
            session['is_admin'] = bool(is_admin)

            flash("Login berhasil!", "success")

            # Buat token acak jika perlu (opsional, hanya untuk keamanan URL)
            random_token = secrets.token_urlsafe(64 if is_admin else 16)

            if is_admin:
                return redirect(url_for('Admin_Dashboard', token=random_token))
            else:
                return redirect(url_for('client_dashboard', token=random_token, url=dashboard_url))
        else:
            flash("Email tidak ditemukan!", "danger")

    return render_template("login.html")

@app.route('/dashboard/<token>')
def client_dashboard(token):
    # Pastikan user sudah login
    if 'email' not in session:
        flash("Anda harus login terlebih dahulu!", "danger")
        return redirect(url_for('login'))

    email_session = session['email']

    # Cari token dan email dari database
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT email FROM users WHERE token = ?", (token,))
    user = cur.fetchone()
    conn.close()

    # Cocokkan email dari session dan database
    if user and user[0] == email_session:
        return render_template("dashboard.html", email=email_session, token=token)

    flash("Akses tidak valid atau token salah!", "danger")
    return redirect(url_for('login'))

@app.route('/admin_dashboard/<token>')
def admin_dashboard(token):
    # 1. Cek apakah sudah login
    if 'email' not in session:
        flash("Anda harus login terlebih dahulu!", "danger")
        return redirect(url_for('login'))

    # 2. Ambil email dari session
    email_session = session['email']

    # 3. Cek apakah email termasuk admin
    if email_session not in ADMIN_EMAILS:
        flash("Akses ditolak. Anda bukan admin!", "danger")
        return redirect(url_for('login'))

    # 4. Cek token di database
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT email FROM users WHERE token = ?", (token,))
    user = cur.fetchone()
    conn.close()

    # 5. Cek apakah token cocok dengan email admin
    if user and user[0] == email_session:
        return render_template("Admin_Dashboard.html", email=email_session, token=token)

    # 6. Kalau token salah
    flash("Akses tidak valid atau token salah!", "danger")
    return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.pop('email', None)
    flash("Logout berhasil!", "info")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=False, use_reloader=False)

