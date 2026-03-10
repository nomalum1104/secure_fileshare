"""
storage.py — Fayl saqlash moduli

Cloudflare R2 yoki AWS S3 orqali fayllarni saqlash.
Muhit o'zgaruvchilari:
  S3_BUCKET         — bucket nomi
  S3_ACCESS_KEY     — access key
  S3_SECRET_KEY     — secret key
  S3_ENDPOINT_URL   — R2 uchun: https://<account>.r2.cloudflarestorage.com
                      S3 uchun: bo'sh qoldiring (avtomatik)
  S3_REGION         — region (masalan: auto yoki us-east-1)
"""

import os
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from cryptography.fernet import Fernet

# ─── S3 / R2 ulanish ──────────────────────────────────────────────────────────

S3_BUCKET      = os.environ.get("S3_BUCKET", "")
S3_ACCESS_KEY  = os.environ.get("S3_ACCESS_KEY", "")
S3_SECRET_KEY  = os.environ.get("S3_SECRET_KEY", "")
S3_ENDPOINT    = os.environ.get("S3_ENDPOINT_URL", "")  # R2 uchun kerak
S3_REGION      = os.environ.get("S3_REGION", "auto")

# Shifrlash kaliti (muhit o'zgaruvchisidan)
FERNET_KEY     = os.environ.get("FERNET_KEY", "")

def _get_fernet() -> Fernet:
    if FERNET_KEY:
        return Fernet(FERNET_KEY.encode())
    # Kalit yo'q bo'lsa — yangi yaratish (faqat development)
    key = Fernet.generate_key()
    print(f"⚠️  FERNET_KEY yo'q! Yangi kalit: {key.decode()}")
    print("    Bu kalitni FERNET_KEY muhit o'zgaruvchisiga qo'shing!")
    return Fernet(key)

_fernet = _get_fernet()

def _get_s3_client():
    kwargs = {
        "aws_access_key_id":     S3_ACCESS_KEY,
        "aws_secret_access_key": S3_SECRET_KEY,
        "region_name":           S3_REGION,
    }
    if S3_ENDPOINT:
        kwargs["endpoint_url"] = S3_ENDPOINT
    return boto3.client("s3", **kwargs)

def is_configured() -> bool:
    """S3/R2 sozlanganligini tekshiradi."""
    return bool(S3_BUCKET and S3_ACCESS_KEY and S3_SECRET_KEY)

# ─── Fayl operatsiyalari ───────────────────────────────────────────────────────

def upload_file(filename: str, data: bytes, owner: str) -> tuple[bool, str]:
    """
    Faylni shifrlaydi va S3/R2 ga yuklaydi.
    Qaytaradi: (ok, s3_key yoki xato xabari)
    """
    if not is_configured():
        return False, "S3/R2 sozlanmagan. Muhit o'zgaruvchilarini kiriting."

    try:
        # Shifrlash
        encrypted = _fernet.encrypt(data)

        # S3 kalit (yo'l): owner/filename
        s3_key = f"files/{owner}/{filename}"

        client = _get_s3_client()
        client.put_object(
            Bucket=S3_BUCKET,
            Key=s3_key,
            Body=encrypted,
            ContentType="application/octet-stream",
            Metadata={
                "owner":    owner,
                "filename": filename,
            }
        )
        return True, s3_key

    except NoCredentialsError:
        return False, "S3 kredensiallar noto'g'ri"
    except ClientError as e:
        return False, f"S3 xato: {e.response['Error']['Message']}"
    except Exception as e:
        return False, f"Yuklash xatosi: {str(e)}"


def download_file(s3_key: str) -> tuple[bool, bytes | str]:
    """
    S3/R2 dan faylni yuklab, shifrlashni ochadi.
    Qaytaradi: (ok, data yoki xato)
    """
    if not is_configured():
        return False, "S3/R2 sozlanmagan"

    try:
        client = _get_s3_client()
        response = client.get_object(Bucket=S3_BUCKET, Key=s3_key)
        encrypted = response["Body"].read()
        data = _fernet.decrypt(encrypted)
        return True, data

    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "NoSuchKey":
            return False, "Fayl topilmadi"
        return False, f"S3 xato: {e.response['Error']['Message']}"
    except Exception as e:
        return False, f"Yuklab olish xatosi: {str(e)}"


def delete_file(s3_key: str) -> tuple[bool, str]:
    """S3/R2 dan faylni o'chiradi."""
    if not is_configured():
        return False, "S3/R2 sozlanmagan"

    try:
        client = _get_s3_client()
        client.delete_object(Bucket=S3_BUCKET, Key=s3_key)
        return True, "Fayl o'chirildi"
    except Exception as e:
        return False, f"O'chirish xatosi: {str(e)}"


def get_presigned_url(s3_key: str, expires: int = 3600) -> str | None:
    """Vaqtinchalik to'g'ridan-to'g'ri yuklab olish URL (ixtiyoriy)."""
    try:
        client = _get_s3_client()
        url = client.generate_presigned_url(
            "get_object",
            Params={"Bucket": S3_BUCKET, "Key": s3_key},
            ExpiresIn=expires
        )
        return url
    except Exception:
        return None
