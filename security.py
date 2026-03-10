"""
security.py — Xavfsizlik moduli

Himoya turlari:
  - Input sanitizatsiya (XSS, injection)
  - Path traversal himoya
  - Filename tozalash
  - Email OTP (SMTP orqali)
  - Umumiy validatsiya funksiyalari
"""

import re
import os
import secrets
import hashlib
import datetime
import smtplib
import html
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path

# ─── Input sanitizatsiya ───────────────────────────────────────────────────────

# Xavfli belgilar ro'yxati (SQL, NoSQL, Shell injection uchun)
_DANGEROUS_PATTERNS = [
    r"('|\")",                          # SQL quote
    r"(--|#|/\*|\*/)",                  # SQL comment
    r"(;|\||\&\&|\|\|)",               # Shell chaining
    r"(\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bDROP\b|\bINSERT\b|\bDELETE\b|\bUPDATE\b)",  # SQL keywords
    r"(<script|</script|javascript:|onerror=|onload=)",  # XSS
    r"(\.\./|\.\.\\|%2e%2e)",          # Path traversal
    r"(\$where|\$ne|\$gt|\$lt|\$regex)",  # NoSQL injection
]

def sanitize_string(value: str, max_len: int = 256) -> tuple[bool, str]:
    """
    Matnni tekshiradi va tozalaydi.
    Qaytaradi: (xavfsiz_mi: bool, tozalangan_qiymat: str)
    """
    if not isinstance(value, str):
        return False, ""

    # Uzunlik cheki
    value = value[:max_len]

    # HTML escape (XSS himoya)
    sanitized = html.escape(value, quote=True)

    # Xavfli pattern tekshiruvi
    for pattern in _DANGEROUS_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            return False, sanitized

    return True, sanitized

def is_safe_username(username: str) -> tuple[bool, str]:
    """Login xavfsizligini tekshiradi."""
    if not username or not isinstance(username, str):
        return False, "Login bo'sh bo'lmasligi kerak"
    if len(username) < 3:
        return False, "Login kamida 3 ta belgidan iborat bo'lishi kerak"
    if len(username) > 32:
        return False, "Login 32 ta belgidan oshmasligi kerak"
    # Faqat xavfsiz belgilar
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Login faqat lotin harflari, raqamlar va _ belgisidan iborat bo'lishi kerak"
    # Tizim loginlari
    banned = {"admin", "root", "superuser", "administrator", "system", "null", "undefined"}
    if username.lower() in banned:
        return False, "Bu login band. Boshqa nom tanlang"
    return True, username

def is_safe_password(password: str) -> tuple[bool, str]:
    """Parol kuchliligini tekshiradi."""
    if not password or len(password) < 8:
        return False, "Parol kamida 8 ta belgidan iborat bo'lishi kerak"
    if len(password) > 128:
        return False, "Parol juda uzun"
    if not re.search(r'[A-Z]', password):
        return False, "Parolda kamida 1 ta KATTA harf bo'lishi kerak (A-Z)"
    if not re.search(r'[a-z]', password):
        return False, "Parolda kamida 1 ta kichik harf bo'lishi kerak (a-z)"
    if not re.search(r'[0-9]', password):
        return False, "Parolda kamida 1 ta raqam bo'lishi kerak (0-9)"
    if not re.search(r'[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]', password):
        return False, "Parolda kamida 1 ta maxsus belgi bo'lishi kerak (!@#$...)"
    return True, password

def safe_filename(filename: str) -> tuple[bool, str]:
    """
    Fayl nomini xavfsiz qiladi.
    Path traversal, null byte, xavfli kengaytmalardan himoya.
    """
    if not filename or not isinstance(filename, str):
        return False, "Fayl nomi bo'sh"

    # Null byte injection
    if '\x00' in filename:
        return False, "Fayl nomida null byte mavjud"

    # Faqat fayl nomini olish (path traversal himoya)
    name = Path(filename).name

    # Bo'sh bo'lsa
    if not name or name in ('.', '..'):
        return False, "Noto'g'ri fayl nomi"

    # Uzunlik cheki
    if len(name) > 255:
        return False, "Fayl nomi juda uzun (max 255)"

    # Xavfli kengaytmalar (server-side execution)
    dangerous_ext = {
        '.exe', '.bat', '.cmd', '.sh', '.ps1', '.vbs', '.js',
        '.php', '.py', '.rb', '.pl', '.cgi', '.htaccess',
        '.jar', '.dll', '.so', '.msi', '.com', '.scr'
    }
    ext = Path(name).suffix.lower()
    if ext in dangerous_ext:
        return False, f"'{ext}' kengaytmali fayllar qabul qilinmaydi"

    # Faqat xavfsiz belgilar
    safe = re.sub(r'[^\w\s.\-]', '_', name)
    safe = re.sub(r'\s+', '_', safe)

    return True, safe

def validate_path_traversal(filename: str, base_dir: Path) -> bool:
    """
    Fayl yo'li base_dir ichida ekanligini tekshiradi.
    Path traversal hujumidan himoya.
    """
    try:
        target = (base_dir / filename).resolve()
        return str(target).startswith(str(base_dir.resolve()))
    except Exception:
        return False

def sanitize_search_query(query: str) -> str:
    """Qidiruv so'rovini tozalaydi."""
    if not query:
        return ""
    # Faqat harflar, raqamlar, bo'sh joy, nuqta, tire
    safe = re.sub(r'[^\w\s.\-]', '', query)
    return safe[:100].strip()

# ─── Email OTP ────────────────────────────────────────────────────────────────

# OTP sozlamalari
OTP_LENGTH     = 6
OTP_EXPIRE_MIN = 10   # 10 daqiqa amal qiladi
OTP_MAX_TRIES  = 3    # 3 marta xato kiritsa bloklash

# Xotira (production da Redis ishlatiladi)
_otp_store: dict = {}   # {username: {code, expires, tries, email}}

# SMTP sozlamalari (foydalanuvchi o'zi to'ldiradi)
SMTP_CONFIG = {
    "host":     os.environ.get("SMTP_HOST", "smtp.gmail.com"),
    "port":     int(os.environ.get("SMTP_PORT", "587")),
    "username": os.environ.get("SMTP_USER", ""),
    "password": os.environ.get("SMTP_PASS", ""),
    "from":     os.environ.get("SMTP_FROM", "noreply@securefileshare.local"),
}

def generate_otp(username: str, email: str) -> tuple[bool, str, str]:
    """
    Yangi OTP yaratadi va email ga yuboradi.
    Qaytaradi: (ok, message, code_for_demo)
    """
    code    = ''.join([str(secrets.randbelow(10)) for _ in range(OTP_LENGTH)])
    expires = datetime.datetime.now() + datetime.timedelta(minutes=OTP_EXPIRE_MIN)

    _otp_store[username] = {
        "code":    hashlib.sha256(code.encode()).hexdigest(),  # hash saqlaymiz
        "expires": expires.isoformat(),
        "tries":   0,
        "email":   email,
    }

    # Email yuborish
    sent = _send_otp_email(email, username, code)

    if sent:
        return True, f"✅ OTP kodi {email} ga yuborildi ({OTP_EXPIRE_MIN} daqiqa amal qiladi)", ""
    else:
        # Demo rejim — email yo'q bo'lsa konsolga chiqarish
        return True, f"📧 Demo rejim: OTP = {code} (konsolda ham ko'rinadi)", code

def verify_otp(username: str, code: str) -> tuple[bool, str]:
    """OTP kodni tekshiradi."""
    entry = _otp_store.get(username)
    if not entry:
        return False, "OTP kodi yuborilmagan. Qaytadan so'rang"

    # Muddati tekshiruvi
    expires = datetime.datetime.fromisoformat(entry["expires"])
    if datetime.datetime.now() > expires:
        _otp_store.pop(username, None)
        return False, "⏰ OTP muddati tugagan. Yangi kod so'rang"

    # Urinishlar soni
    if entry["tries"] >= OTP_MAX_TRIES:
        _otp_store.pop(username, None)
        return False, "🚫 Juda ko'p urinish. Yangi OTP so'rang"

    # Kod tekshiruvi (hash bilan solishtirish)
    if hashlib.sha256(code.encode()).hexdigest() != entry["code"]:
        entry["tries"] += 1
        left = OTP_MAX_TRIES - entry["tries"]
        return False, f"❌ Noto'g'ri kod. {left} ta urinish qoldi"

    # To'g'ri! — o'chirish
    _otp_store.pop(username, None)
    return True, "✅ OTP tasdiqlandi"

def otp_is_pending(username: str) -> bool:
    """Foydalanuvchi uchun faol OTP borligini tekshiradi."""
    entry = _otp_store.get(username)
    if not entry:
        return False
    expires = datetime.datetime.fromisoformat(entry["expires"])
    return datetime.datetime.now() < expires

def _send_otp_email(to_email: str, username: str, code: str) -> bool:
    """SMTP orqali OTP yuboradi."""
    if not SMTP_CONFIG["username"] or not SMTP_CONFIG["password"]:
        # SMTP sozlanmagan — demo rejim
        print(f"\n{'='*50}")
        print(f"📧 OTP EMAIL (Demo rejim)")
        print(f"   Foydalanuvchi : {username}")
        print(f"   Email         : {to_email}")
        print(f"   OTP kodi      : {code}")
        print(f"   Muddat        : {OTP_EXPIRE_MIN} daqiqa")
        print(f"{'='*50}\n")
        return False   # False = demo rejim

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[SecureFileShare] Tasdiqlash kodi: {code}"
        msg["From"]    = SMTP_CONFIG["from"]
        msg["To"]      = to_email

        html_body = f"""
        <html><body style="font-family:Arial,sans-serif;background:#0b0d12;color:#e2e8f0;padding:40px;">
          <div style="max-width:400px;margin:0 auto;background:#12151e;border-radius:12px;
                      padding:32px;border:1px solid rgba(255,255,255,0.08);">
            <h2 style="color:#6366f1;margin-bottom:8px;">🔒 SecureFileShare</h2>
            <p>Salom <strong>{username}</strong>,</p>
            <p>Tasdiqlash kodingiz:</p>
            <div style="font-size:36px;font-weight:bold;letter-spacing:12px;
                        background:#1a1d2a;padding:20px;border-radius:8px;
                        text-align:center;color:#6366f1;margin:20px 0;">
              {code}
            </div>
            <p style="color:#64748b;font-size:13px;">
              Bu kod <strong>{OTP_EXPIRE_MIN} daqiqa</strong> amal qiladi.<br>
              Agar siz so'ramagan bo'lsangiz, bu xatni e'tiborsiz qoldiring.
            </p>
          </div>
        </body></html>
        """
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(SMTP_CONFIG["host"], SMTP_CONFIG["port"]) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_CONFIG["username"], SMTP_CONFIG["password"])
            server.sendmail(SMTP_CONFIG["from"], to_email, msg.as_string())
        return True
    except Exception as e:
        print(f"SMTP xato: {e}")
        return False
