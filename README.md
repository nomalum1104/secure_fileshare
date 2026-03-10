# 🔒 Secure File Share — Production

Flask + PostgreSQL + S3/R2 + Email SMTP + 2FA

---

## 🚀 Deploy qilish — bosqichma-bosqich

### 1-qadam: GitHub reponi yarating

```bash
git init
git add .
git commit -m "Initial production deploy"
```

GitHub.com → New repository → `secure-fileshare` → push qiling

---

### 2-qadam: Cloudflare R2 (bepul fayl saqlash)

1. https://dash.cloudflare.com → **R2** bo'limiga kiring
2. **Create bucket** → nom bering (masalan: `secure-fileshare-files`)
3. **Manage R2 API Tokens** → Create Token:
   - Permissions: **Object Read & Write**
   - Specify bucket → o'z bucket nomingizni tanlang
4. Quyidagilarni saqlang:
   - `Access Key ID` → `S3_ACCESS_KEY`
   - `Secret Access Key` → `S3_SECRET_KEY`
   - `Account ID` → endpoint URL uchun kerak
5. Endpoint: `https://YOUR_ACCOUNT_ID.r2.cloudflarestorage.com`

> 💡 R2 — oyiga 10GB bepul, egress to'lovi yo'q!

---

### 3-qadam: Gmail SMTP sozlash

1. Gmail → **Google Account** → **Security**
2. **2-Step Verification** → yoqing
3. **App passwords** → `Mail` → `Windows Computer`
4. 16 ta belgili parol olinadi → `SMTP_PASS` ga kiriting

---

### 4-qadam: Railway deploy

1. https://railway.app → **Login with GitHub**
2. **New Project** → **Deploy from GitHub repo** → reponi tanlang
3. **Add Plugin** → **PostgreSQL** → qo'shing
   - `DATABASE_URL` avtomatik o'rnatiladi ✅
4. **Variables** bo'limiga quyidagilarni qo'shing:

```
SECRET_KEY         = (python -c "import secrets; print(secrets.token_hex(32))")
FERNET_KEY         = (python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
S3_BUCKET          = secure-fileshare-files
S3_ACCESS_KEY      = (R2 dan)
S3_SECRET_KEY      = (R2 dan)
S3_ENDPOINT_URL    = https://ACCOUNT_ID.r2.cloudflarestorage.com
S3_REGION          = auto
SMTP_HOST          = smtp.gmail.com
SMTP_PORT          = 587
SMTP_USER          = sizning@gmail.com
SMTP_PASS          = (16 ta belgili App Password)
SMTP_FROM          = sizning@gmail.com
```

5. **Deploy** → bir necha daqiqada tayyor! 🎉

---

### 5-qadam: Domen ulash (ixtiyoriy)

Railway → Settings → **Domains** → Custom domain qo'shing

Cloudflare DNS:
```
CNAME   www   your-app.railway.app   (Proxied)
```

---

## 🔑 Birinchi kirish

```
Login:  admin
Parol:  Admin@123!
```

> ⚠️ Birinchi kirishdan so'ng parolni o'zgartiring!

---

## 🛡️ Xavfsizlik imkoniyatlari

| Xususiyat | Holat |
|-----------|-------|
| AES-256 shifrlash | ✅ |
| CSRF himoya | ✅ |
| Brute-force bloklash | ✅ |
| Session timeout (30 min) | ✅ |
| TOTP 2FA (Google Auth) | ✅ |
| Email OTP | ✅ |
| SQL Injection himoya | ✅ |
| XSS himoya | ✅ |
| Path traversal himoya | ✅ |
| Kuchli parol talabi | ✅ |
| RBAC (admin/editor/viewer) | ✅ |
| Audit log | ✅ |
| HTTPS (Railway) | ✅ |

---

## 📦 Stack

- **Backend**: Python 3.11 + Flask
- **Database**: PostgreSQL (Railway)
- **Storage**: Cloudflare R2 / AWS S3
- **Email**: Gmail SMTP / boshqa SMTP
- **Hosting**: Railway
- **Shifrlash**: AES-256 (Fernet)
