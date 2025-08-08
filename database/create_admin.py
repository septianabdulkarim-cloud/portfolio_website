import sqlite3
import uuid

# Ubah ke nama file SQLite kamu
DATABASE = 'your_database.db'  # Ganti kalau pakai nama lain

def create_admin():
    email = 'septianabdulkarim@gmail.com'  # Ganti sesuai kebutuhan
    token = 'manual-token'
    is_verified = 1
    is_admin = 1
    dashboard_url = str(uuid.uuid4())  # Generate UUID untuk dashboard admin

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    # Cek apakah admin sudah ada
    c.execute("SELECT * FROM users WHERE email = ?", (email,))
    if c.fetchone():
        print("Admin sudah ada di database.")
        conn.close()
        return

    # Insert admin user
    c.execute('''
        INSERT INTO users (email, token, is_verified, is_admin, dashboard_url)
        VALUES (?, ?, ?, ?, ?)
    ''', (email, token, is_verified, is_admin, dashboard_url))

    conn.commit()
    conn.close()
    print(f"Admin berhasil dibuat dengan email: {email}")
    print(f"Dashboard URL: {dashboard_url}")

if __name__ == "__main__":
    create_admin()
