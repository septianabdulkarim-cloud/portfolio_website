from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from database.db import get_db_connection, init_db
from dotenv import load_dotenv
from flask import send_from_directory
from markupsafe import escape
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import os, uuid, logging




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
        email = s.loads(token, salt='email-confirm', max_age=3600)
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE users SET is_verified = 1 WHERE email = ?", (email,))
        conn.commit()
        conn.close()

        flash("Email berhasil diverifikasi! Silakan login.", "success")
        logging.info(f"Email verified: {email}")
    except Exception as e:
        logging.error(f"Verifikasi gagal: {e}")
        flash("Link tidak valid atau kedaluwarsa!", "danger")
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", error_message="Terlalu banyak percobaan login. Coba lagi nanti.")
def login():
    if request.method == 'POST':
        # Escape input untuk hindari XSS
        email = escape(request.form['email'].strip().lower())

        if not email or '@' not in email:
            flash("Format email tidak valid!", "danger")
            return render_template("login.html")

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT token, is_verified FROM users WHERE email = ?", (email,))
        user = cur.fetchone()
        conn.close()

        if user:
            token, verified = user
            if verified:
                session['email'] = email
                flash("Login berhasil!", "success")

                # Cek apakah email adalah admin
                if email in ADMIN_EMAILS:
                    return redirect(url_for('admin_dashboard', token=token))
                else:
                    return redirect(url_for('client_dashboard', token=token))
            else:
                flash("Akun belum diverifikasi!", "warning")
        else:
            flash("Email tidak ditemukan!", "danger")

    return render_template("login.html")


@app.route('/dashboard/<token>')
def client_dashboard(token):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT email FROM users WHERE token = ?", (token,))
    user = cur.fetchone()
    conn.close()

    if user and 'email' in session and session['email'] == user[0]:
        return render_template("dashboard.html", email=user[0])
    flash("Anda harus login terlebih dahulu!", "danger")
    return redirect(url_for('login'))

@app.route('/admin')
def admin():
    return send_from_directory('admin_build', 'index.html')

@app.route('/admin/<path:path>')
def admin_static(path):
    return send_from_directory('admin_build', path)

@app.route('/logout')
def logout():
    session.pop('email', None)
    flash("Logout berhasil!", "info")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=False, use_reloader=False)

