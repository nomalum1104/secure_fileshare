"""
core.py — Production versiya
PostgreSQL + S3/R2 + Email SMTP + 2FA + OTP
"""

import os
import hashlib
import hmac
import struct
import time
import base64
import datetime
import secrets
from database import init_db, fetchone, fetchall, execute
from storage import upload_file as s3_upload, download_file as s3_download, delete_file as s3_delete
from security import (
    is_safe_username, is_safe_password, safe_filename,
    validate_path_traversal, sanitize_search_query,
    generate_otp, verify_otp, otp_is_pending
)

# ─── RBAC ─────────────────────────────────────────────────────────────────────

ROLE_PERMISSIONS = {
    "admin":  {"upload", "download", "delete", "share", "view_logs"},
    "editor": {"upload", "download", "share"},
    "viewer": {"download"},
}

# ─── Brute-force ──────────────────────────────────────────────────────────────

MAX_ATTEMPTS     = 5
BAN_MINUTES      = 15
_failed_attempts = {}

# ─── Parol ────────────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h    = hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
    return f"{salt}:{h}"

def verify_password(password: str, stored: str) -> bool:
    try:
        salt, h = stored.split(":", 1)
        return hmac.compare_digest(
            hashlib.sha256(f"{salt}{password}".encode()).hexdigest(), h
        )
    except Exception:
        return False

# ─── TOTP 2FA ─────────────────────────────────────────────────────────────────

def _totp_generate_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode()

def _hotp(secret: str, counter: int) -> int:
    key = base64.b32decode(secret.upper())
    msg = struct.pack(">Q", counter)
    h   = hmac.new(key, msg, hashlib.sha1).digest()
    off = h[-1] & 0x0F
    return (struct.unpack(">I", h[off:off+4])[0] & 0x7FFFFFFF) % 1_000_000

def totp_now(secret: str) -> str:
    return f"{_hotp(secret, int(time.time())//30):06d}"

def totp_verify(secret: str, code: str) -> bool:
    if not code or len(code) != 6 or not code.isdigit():
        return False
    t = int(time.time()) // 30
    return any(f"{_hotp(secret, t+d):06d}" == code for d in (-1, 0, 1))

def totp_otpauth_url(secret: str, username: str) -> str:
    import urllib.parse
    label  = urllib.parse.quote(f"SecureFileShare:{username}")
    params = urllib.parse.urlencode({
        "secret": secret, "issuer": "SecureFileShare",
        "algorithm": "SHA1", "digits": 6, "period": 30
    })
    return f"otpauth://totp/{label}?{params}"

# ─── Audit log ────────────────────────────────────────────────────────────────

def write_log(username: str, action: str, detail: str = "", ip: str = ""):
    execute(
        "INSERT INTO audit_log (username, action, detail, ip_address) VALUES (%s,%s,%s,%s)",
        (username, action, detail, ip)
    )

# ─── Asosiy tizim ─────────────────────────────────────────────────────────────

class FileShareSystem:

    def __init__(self):
        init_db()
        self._ensure_admin()

    def _ensure_admin(self):
        if not fetchone("SELECT 1 FROM users WHERE username=%s", ("admin",)):
            execute(
                """INSERT INTO users (username, password_hash, role)
                   VALUES (%s,%s,'admin')""",
                ("admin", hash_password("Admin@123!"))
            )
            print("✅ Admin yaratildi: admin / Admin@123!")

    # ── Auth ──────────────────────────────────────────────────────────────────

    def register(self, username: str, password: str, role: str = "viewer"):
        ok, msg = is_safe_username(username)
        if not ok:
            return False, msg
        ok, msg = is_safe_password(password)
        if not ok:
            return False, msg
        if fetchone("SELECT 1 FROM users WHERE username=%s", (username,)):
            return False, f"'{username}' allaqachon mavjud"
        execute(
            "INSERT INTO users (username, password_hash, role) VALUES (%s,%s,'viewer')",
            (username, hash_password(password))
        )
        write_log(username, "REGISTER", "role=viewer")
        return True, f"'{username}' muvaffaqiyatli ro'yxatdan o'tdi"

    def login(self, username: str, password: str, ip: str = "unknown"):
        now = datetime.datetime.now()
        attempts = [t for t in _failed_attempts.get(username, [])
                    if (now - t).total_seconds() < BAN_MINUTES * 60]
        _failed_attempts[username] = attempts
        if len(attempts) >= MAX_ATTEMPTS:
            wait = BAN_MINUTES - int((now - attempts[0]).total_seconds() / 60)
            write_log(username, "LOGIN_BLOCKED", f"ip={ip}")
            return False, f"🚫 Akkaunt {wait} daqiqaga bloklangan"

        user = fetchone("SELECT * FROM users WHERE username=%s", (username,))
        if not user or not verify_password(password, user["password_hash"]):
            attempts.append(now)
            _failed_attempts[username] = attempts
            left = MAX_ATTEMPTS - len(attempts)
            write_log(username, "LOGIN_FAIL", f"ip={ip}")
            if left > 0:
                return False, f"❌ Noto'g'ri login yoki parol. {left} ta urinish qoldi"
            return False, f"🚫 Akkaunt {BAN_MINUTES} daqiqaga bloklandi!"

        _failed_attempts.pop(username, None)
        execute(
            "UPDATE users SET last_login=%s, last_ip=%s WHERE username=%s",
            (now, ip, username)
        )
        write_log(username, "LOGIN_OK", f"ip={ip}")
        return True, "✅ Kirish muvaffaqiyatli"

    def change_password(self, username: str, old_pw: str, new_pw: str):
        user = fetchone("SELECT password_hash FROM users WHERE username=%s", (username,))
        if not user or not verify_password(old_pw, user["password_hash"]):
            return False, "Eski parol noto'g'ri"
        ok, msg = is_safe_password(new_pw)
        if not ok:
            return False, msg
        execute("UPDATE users SET password_hash=%s WHERE username=%s",
                (hash_password(new_pw), username))
        write_log(username, "CHANGE_PASSWORD")
        return True, "Parol muvaffaqiyatli o'zgartirildi"

    def admin_change_password(self, admin: str, target: str, new_pw: str):
        if not self._is_admin(admin):
            return False, "Faqat admin"
        ok, msg = is_safe_password(new_pw)
        if not ok:
            return False, msg
        execute("UPDATE users SET password_hash=%s WHERE username=%s",
                (hash_password(new_pw), target))
        write_log(admin, "ADMIN_CHANGE_PASSWORD", f"target={target}")
        return True, f"'{target}' paroli o'zgartirildi"

    def change_role(self, admin: str, target: str, new_role: str):
        if not self._is_admin(admin):
            return False, "Faqat admin"
        if admin == target:
            return False, "O'z rolingizni o'zgartira olmaysiz"
        if new_role not in ROLE_PERMISSIONS:
            return False, "Noto'g'ri rol"
        old = (fetchone("SELECT role FROM users WHERE username=%s", (target,)) or {}).get("role","?")
        execute("UPDATE users SET role=%s WHERE username=%s", (new_role, target))
        write_log(admin, "CHANGE_ROLE", f"target={target} {old}→{new_role}")
        return True, f"'{target}' roli {old} → {new_role}"

    def update_profile(self, username: str, display_name: str = "", email: str = ""):
        execute("UPDATE users SET display_name=%s, email=%s WHERE username=%s",
                (display_name or None, email or None, username))
        write_log(username, "UPDATE_PROFILE")
        return True, "Profil yangilandi"

    def get_profile(self, username: str) -> dict:
        u = fetchone("SELECT * FROM users WHERE username=%s", (username,))
        if not u:
            return {}
        files_count  = fetchone("SELECT COUNT(*) AS c FROM files WHERE owner=%s", (username,))
        shared_count = fetchone("SELECT COUNT(*) AS c FROM acl WHERE username=%s", (username,))
        return {
            "username":     username,
            "role":         u.get("role", "viewer"),
            "display_name": u.get("display_name", "") or "",
            "email":        u.get("email", "") or "",
            "last_login":   str(u.get("last_login", ""))[:16],
            "last_ip":      u.get("last_ip", ""),
            "total_files":  (files_count or {}).get("c", 0),
            "shared_files": (shared_count or {}).get("c", 0),
            "totp_enabled": bool(u.get("totp_enabled", False)),
        }

    # ── Fayllar ───────────────────────────────────────────────────────────────

    def upload_file(self, username: str, filename: str, data: bytes):
        if not self._has_perm(username, "upload"):
            return False, "Ruxsat yo'q"
        ok, safe_name = safe_filename(filename)
        if not ok:
            return False, f"Xavfli fayl nomi: {safe_name}"
        if len(data) > 50 * 1024 * 1024:
            return False, "Fayl 50MB dan oshmasligi kerak"

        ok, result = s3_upload(safe_name, data, username)
        if not ok:
            return False, result

        execute(
            """INSERT INTO files (filename, owner, size_bytes, s3_key)
               VALUES (%s,%s,%s,%s)
               ON CONFLICT (filename) DO UPDATE
               SET size_bytes=%s, s3_key=%s, uploaded_at=NOW()""",
            (safe_name, username, len(data), result, len(data), result)
        )
        write_log(username, "UPLOAD", f"file={safe_name} size={len(data)}")
        return True, f"'{safe_name}' yuklandi va shifrlandi"

    def download_file(self, username: str, filename: str):
        if not self._can_access(username, filename, "read"):
            return False, "Ruxsat yo'q", None
        row = fetchone("SELECT s3_key FROM files WHERE filename=%s", (filename,))
        if not row:
            return False, "Fayl topilmadi", None
        ok, data = s3_download(row["s3_key"])
        if not ok:
            return False, data, None
        write_log(username, "DOWNLOAD", f"file={filename}")
        return True, "OK", data

    def delete_file(self, username: str, filename: str):
        row = fetchone("SELECT owner, s3_key FROM files WHERE filename=%s", (filename,))
        if not row:
            return False, "Fayl topilmadi"
        if row["owner"] != username and not self._is_admin(username):
            return False, "Ruxsat yo'q"
        s3_delete(row["s3_key"])
        execute("DELETE FROM files WHERE filename=%s", (filename,))
        write_log(username, "DELETE", f"file={filename}")
        return True, f"'{filename}' o'chirildi"

    def list_files(self, username: str) -> list:
        rows = fetchall(
            """SELECT f.filename, f.owner, f.size_bytes, f.uploaded_at,
                      a.permission
               FROM files f
               LEFT JOIN acl a ON a.filename=f.filename AND a.username=%s
               WHERE f.owner=%s OR a.username=%s
               ORDER BY f.uploaded_at DESC""",
            (username, username, username)
        )
        result = []
        for r in rows:
            result.append({
                "name":        r["filename"],
                "owner":       r["owner"],
                "size":        r["size_bytes"],
                "uploaded_at": str(r["uploaded_at"]),
                "is_owner":    r["owner"] == username,
                "permission":  "write" if r["owner"] == username else (r["permission"] or "read"),
            })
        return result

    def search_files(self, username: str, query: str) -> list:
        query = sanitize_search_query(query)
        all_files = self.list_files(username)
        if not query:
            return all_files
        q = query.lower()
        return [f for f in all_files if q in f["name"].lower() or q in f["owner"].lower()]

    # ── ACL ───────────────────────────────────────────────────────────────────

    def share_file(self, owner: str, filename: str, target: str, permission: str):
        if not self._can_access(owner, filename, "read"):
            return False, "Ruxsat yo'q"
        if not fetchone("SELECT 1 FROM users WHERE username=%s", (target,)):
            return False, f"'{target}' foydalanuvchi topilmadi"
        if permission not in ("read", "write"):
            permission = "read"
        execute(
            """INSERT INTO acl (filename, username, permission)
               VALUES (%s,%s,%s)
               ON CONFLICT (filename,username) DO UPDATE SET permission=%s""",
            (filename, target, permission, permission)
        )
        write_log(owner, "SHARE", f"file={filename} to={target} perm={permission}")
        return True, f"'{target}' ga ruxsat berildi"

    def revoke_access(self, owner: str, filename: str, target: str):
        row = fetchone("SELECT owner FROM files WHERE filename=%s", (filename,))
        if not row or (row["owner"] != owner and not self._is_admin(owner)):
            return False, "Ruxsat yo'q"
        execute("DELETE FROM acl WHERE filename=%s AND username=%s", (filename, target))
        write_log(owner, "REVOKE", f"file={filename} from={target}")
        return True, f"'{target}' ruxsati olib qo'yildi"

    def get_acl(self, requester: str, filename: str) -> dict:
        row = fetchone("SELECT owner FROM files WHERE filename=%s", (filename,))
        if not row or (row["owner"] != requester and not self._is_admin(requester)):
            return {}
        rows = fetchall("SELECT username, permission FROM acl WHERE filename=%s", (filename,))
        return {r["username"]: r["permission"] for r in rows}

    # ── Share links ───────────────────────────────────────────────────────────

    def create_share_link(self, username: str, filename: str, hours: int = 24):
        if not self._can_access(username, filename, "read"):
            return False, "Ruxsat yo'q", None
        token   = secrets.token_urlsafe(32)
        expires = datetime.datetime.now() + datetime.timedelta(hours=hours)
        execute(
            "INSERT INTO share_links (token,filename,created_by,expires_at) VALUES (%s,%s,%s,%s)",
            (token, filename, username, expires)
        )
        write_log(username, "CREATE_LINK", f"file={filename} hours={hours}")
        return True, "Havola yaratildi", token

    def get_share_link(self, token: str):
        row = fetchone(
            "SELECT * FROM share_links WHERE token=%s AND expires_at > NOW()",
            (token,)
        )
        return row

    def list_links(self, username: str) -> list:
        rows = fetchall(
            "SELECT * FROM share_links WHERE created_by=%s ORDER BY created_at DESC",
            (username,)
        )
        now = datetime.datetime.now()
        result = []
        for r in rows:
            exp = r["expires_at"]
            if hasattr(exp, "replace"):
                exp = exp.replace(tzinfo=None)
            result.append({
                "token":    r["token"],
                "filename": r["filename"],
                "expires":  str(r["expires_at"])[:16],
                "active":   exp > now,
            })
        return result

    def delete_link(self, username: str, token: str):
        execute("DELETE FROM share_links WHERE token=%s AND created_by=%s", (token, username))
        return True, "Havola o'chirildi"

    # ── Logs ──────────────────────────────────────────────────────────────────

    def get_logs(self, limit: int = 100) -> list:
        rows = fetchall(
            "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT %s", (limit,)
        )
        return [
            f"{str(r['created_at'])[:19]} | {r['username'] or '-':16} | {r['action']:24} | {r['detail'] or ''} | ip={r['ip_address'] or ''}"
            for r in rows
        ]

    def get_stats(self) -> dict:
        users_count = (fetchone("SELECT COUNT(*) AS c FROM users") or {}).get("c", 0)
        files_count = (fetchone("SELECT COUNT(*) AS c FROM files") or {}).get("c", 0)
        files_size  = (fetchone("SELECT COALESCE(SUM(size_bytes),0) AS s FROM files") or {}).get("s", 0)
        links_count = (fetchone("SELECT COUNT(*) AS c FROM share_links WHERE expires_at>NOW()") or {}).get("c", 0)
        top_users   = fetchall(
            "SELECT owner, COUNT(*) AS cnt FROM files GROUP BY owner ORDER BY cnt DESC LIMIT 5"
        )
        return {
            "users":   users_count,
            "files":   files_count,
            "size_mb": round(int(files_size) / 1024 / 1024, 2),
            "links":   links_count,
            "top":     [{"username": r["owner"], "files": r["cnt"]} for r in top_users],
        }

    def list_users(self) -> list:
        rows = fetchall(
            "SELECT username, role, display_name, email, last_login FROM users ORDER BY username"
        )
        return [dict(r) for r in rows]

    # ── 2FA ───────────────────────────────────────────────────────────────────

    def needs_2fa(self, username: str) -> bool:
        u = fetchone("SELECT totp_enabled FROM users WHERE username=%s", (username,))
        return bool(u and u.get("totp_enabled"))

    def setup_2fa(self, username: str):
        secret = _totp_generate_secret()
        execute("UPDATE users SET totp_pending=%s WHERE username=%s", (secret, username))
        return True, "QR kodni skanerlang", totp_otpauth_url(secret, username)

    def confirm_2fa(self, username: str, code: str):
        u = fetchone("SELECT totp_pending FROM users WHERE username=%s", (username,))
        if not u or not u.get("totp_pending"):
            return False, "Avval 2FA sozlamasini boshlang"
        if not totp_verify(u["totp_pending"], code):
            return False, "❌ Noto'g'ri kod"
        execute(
            "UPDATE users SET totp_secret=%s, totp_pending=NULL, totp_enabled=TRUE WHERE username=%s",
            (u["totp_pending"], username)
        )
        write_log(username, "2FA_ENABLED")
        return True, "✅ 2FA muvaffaqiyatli yoqildi!"

    def disable_2fa(self, username: str, code: str):
        u = fetchone("SELECT totp_secret, totp_enabled FROM users WHERE username=%s", (username,))
        if not u or not u.get("totp_enabled"):
            return False, "2FA allaqachon o'chiq"
        if not totp_verify(u["totp_secret"] or "", code):
            return False, "❌ Noto'g'ri kod"
        execute("UPDATE users SET totp_enabled=FALSE, totp_secret=NULL WHERE username=%s", (username,))
        write_log(username, "2FA_DISABLED")
        return True, "2FA o'chirildi"

    def verify_2fa(self, username: str, code: str) -> bool:
        u = fetchone("SELECT totp_enabled, totp_secret FROM users WHERE username=%s", (username,))
        if not u or not u.get("totp_enabled"):
            return True
        return totp_verify(u.get("totp_secret", ""), code)

    # ── Email OTP ─────────────────────────────────────────────────────────────

    def send_email_otp(self, username: str):
        u = fetchone("SELECT email FROM users WHERE username=%s", (username,))
        if not u or not u.get("email"):
            return False, "Profilingizda email yo'q. Avval emailingizni kiriting.", ""
        return generate_otp(username, u["email"])

    def check_email_otp(self, username: str, code: str):
        ok, msg = verify_otp(username, code)
        write_log(username, "EMAIL_OTP_OK" if ok else "EMAIL_OTP_FAIL")
        return ok, msg

    def has_email_otp_pending(self, username: str) -> bool:
        return otp_is_pending(username)

    # ── Ichki yordamchilar ────────────────────────────────────────────────────

    def _is_admin(self, username: str) -> bool:
        u = fetchone("SELECT role FROM users WHERE username=%s", (username,))
        return bool(u and u.get("role") == "admin")

    def _has_perm(self, username: str, perm: str) -> bool:
        u = fetchone("SELECT role FROM users WHERE username=%s", (username,))
        if not u:
            return False
        return perm in ROLE_PERMISSIONS.get(u["role"], set())

    def _can_access(self, username: str, filename: str, perm: str) -> bool:
        f = fetchone("SELECT owner FROM files WHERE filename=%s", (filename,))
        if not f:
            return False
        if f["owner"] == username or self._is_admin(username):
            return True
        acl = fetchone(
            "SELECT permission FROM acl WHERE filename=%s AND username=%s",
            (filename, username)
        )
        if not acl:
            return False
        if perm == "read":
            return acl["permission"] in ("read", "write")
        return acl["permission"] == "write"
