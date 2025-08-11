import sqlite3

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    # Tabel users_client
    cur.execute('''
    CREATE TABLE IF NOT EXISTS users_client (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        token TEXT NOT NULL,
        dashboard_url TEXT NOT NULL,
        verified INTEGER NOT NULL DEFAULT 0
    )
    ''')
    # Tabel users_admin
    cur.execute('''
    CREATE TABLE IF NOT EXISTS users_admin (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        token TEXT NOT NULL,
        dashboard_url TEXT NOT NULL,
        verified INTEGER NOT NULL DEFAULT 0
    )
    ''')
    conn.commit()
    conn.close()
