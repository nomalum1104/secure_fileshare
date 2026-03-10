"""
database.py — PostgreSQL baza moduli

JSON fayldan PostgreSQL ga to'liq ko'chirish.
Railway da DATABASE_URL muhit o'zgaruvchisi avtomatik o'rnatiladi.
"""

import os
import psycopg2
import psycopg2.extras
from contextlib import contextmanager

DATABASE_URL = os.environ.get("DATABASE_URL", "")

# Railway PostgreSQL URL ni psycopg2 formatiga o'tkazish
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)


@contextmanager
def get_conn():
    """Kontekst menejeri — ulanish avtomatik yopiladi."""
    conn = psycopg2.connect(DATABASE_URL)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Jadvallarni yaratish (birinchi ishga tushirishda)."""
    with get_conn() as conn:
        cur = conn.cursor()

        # Foydalanuvchilar jadvali
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username        VARCHAR(64) PRIMARY KEY,
                password_hash   VARCHAR(256) NOT NULL,
                role            VARCHAR(16)  NOT NULL DEFAULT 'viewer',
                display_name    VARCHAR(128),
                email           VARCHAR(256),
                last_login      TIMESTAMP,
                last_ip         VARCHAR(64),
                totp_enabled    BOOLEAN DEFAULT FALSE,
                totp_secret     VARCHAR(64),
                totp_pending    VARCHAR(64),
                created_at      TIMESTAMP DEFAULT NOW()
            )
        """)

        # Fayllar jadvali
        cur.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id              SERIAL PRIMARY KEY,
                filename        VARCHAR(256) NOT NULL UNIQUE,
                owner           VARCHAR(64)  NOT NULL REFERENCES users(username) ON DELETE CASCADE,
                size_bytes      BIGINT       NOT NULL DEFAULT 0,
                s3_key          VARCHAR(512),
                uploaded_at     TIMESTAMP    DEFAULT NOW()
            )
        """)

        # ACL jadvali (kim qaysi faylga qanday kirishi mumkin)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS acl (
                id          SERIAL PRIMARY KEY,
                filename    VARCHAR(256) NOT NULL REFERENCES files(filename) ON DELETE CASCADE,
                username    VARCHAR(64)  NOT NULL REFERENCES users(username) ON DELETE CASCADE,
                permission  VARCHAR(8)   NOT NULL CHECK (permission IN ('read','write')),
                granted_at  TIMESTAMP    DEFAULT NOW(),
                UNIQUE (filename, username)
            )
        """)

        # Havolalar jadvali
        cur.execute("""
            CREATE TABLE IF NOT EXISTS share_links (
                token       VARCHAR(64)  PRIMARY KEY,
                filename    VARCHAR(256) NOT NULL REFERENCES files(filename) ON DELETE CASCADE,
                created_by  VARCHAR(64)  NOT NULL REFERENCES users(username) ON DELETE CASCADE,
                expires_at  TIMESTAMP    NOT NULL,
                created_at  TIMESTAMP    DEFAULT NOW()
            )
        """)

        # Audit log jadvali
        cur.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id          SERIAL PRIMARY KEY,
                username    VARCHAR(64),
                action      VARCHAR(64)  NOT NULL,
                detail      TEXT,
                ip_address  VARCHAR(64),
                created_at  TIMESTAMP    DEFAULT NOW()
            )
        """)

        # Indekslar — tezroq qidirish uchun
        cur.execute("CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_acl_username ON acl(username)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_username ON audit_log(username)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_links_expires ON share_links(expires_at)")

        print("✅ PostgreSQL jadvallari tayyor")


# ─── Yordamchi funksiyalar ─────────────────────────────────────────────────────

def fetchone(sql: str, params=()) -> dict | None:
    with get_conn() as conn:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql, params)
        row = cur.fetchone()
        return dict(row) if row else None

def fetchall(sql: str, params=()) -> list:
    with get_conn() as conn:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]

def execute(sql: str, params=()) -> int:
    """INSERT/UPDATE/DELETE. rowcount qaytaradi."""
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(sql, params)
        return cur.rowcount
