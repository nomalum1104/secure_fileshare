"""
Secure File Sharing System — Web Interface
Production: PostgreSQL + S3/R2
"""

from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash, jsonify, abort
import os
import secrets
import datetime
from functools import wraps
from core import FileShareSystem

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["PERMANENT_SESSION_LIFETIME"] = datetime.timedelta(minutes=30)

system = FileShareSystem()

# ─── Helpers ─────────────────────────────────────────────────────────────────

def current_user():
    return session.get("username")

def get_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")

def require_login(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        last_active = session.get("last_active")
        if last_active:
            diff = (datetime.datetime.now() - datetime.datetime.fromisoformat(last_active)).total_seconds()
            if diff > 30 * 60:
                session.clear()
                flash("⏰ Sessiya muddati tugadi. Qayta kiring.", "error")
                return redirect(url_for("login"))
        session["last_active"] = datetime.datetime.now().isoformat()
        session.permanent = True
        return f(*args, **kwargs)
    return wrapper

def generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]

def check_csrf():
    token = request.form.get("csrf_token")
    if not token or token != session.get("csrf_token"):
        abort(403)

app.jinja_env.globals["csrf_token"] = generate_csrf_token

# ─── Auth Routes ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if current_user():
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        check_csrf()
        username = request.form["username"]
        password = request.form["password"]
        ok, msg = system.login(username, password, get_ip())
        if ok:
            if system.needs_2fa(username):
                session["2fa_pending"] = username
                session["last_active"] = datetime.datetime.now().isoformat()
                return redirect(url_for("login_2fa"))
            session["username"] = username
            session["last_active"] = datetime.datetime.now().isoformat()
            session.permanent = True
            generate_csrf_token()
            return redirect(url_for("dashboard"))
        flash(msg, "error")
    return render_template("login.html")

@app.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    pending = session.get("2fa_pending")
    if not pending:
        return redirect(url_for("login"))
    if request.method == "POST":
        check_csrf()
        code = request.form.get("code", "").strip()
        if system.verify_2fa(pending, code):
            session.pop("2fa_pending", None)
            session["username"] = pending
            session["last_active"] = datetime.datetime.now().isoformat()
            session.permanent = True
            generate_csrf_token()
            return redirect(url_for("dashboard"))
        flash("❌ Noto'g'ri 2FA kod.", "error")
    return render_template("login_2fa.html")

@app.route("/login/otp", methods=["GET", "POST"])
def login_otp():
    if request.method == "POST":
        check_csrf()
        action = request.form.get("action")
        if action == "request":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()
            ok, msg = system.login(username, password, get_ip())
            if ok:
                ok2, msg2, demo_code = system.send_email_otp(username)
                flash(msg2, "success" if ok2 else "error")
                if demo_code:
                    flash(f"🧪 Demo OTP: {demo_code}", "success")
                if ok2:
                    session["otp_pending"] = username
                    return redirect(url_for("login_otp"))
            else:
                flash(msg, "error")
        elif action == "verify":
            pending = session.get("otp_pending")
            if not pending:
                return redirect(url_for("login_otp"))
            code = request.form.get("code", "").strip()
            ok, msg = system.check_email_otp(pending, code)
            if ok:
                session.pop("otp_pending", None)
                session["username"] = pending
                session["last_active"] = datetime.datetime.now().isoformat()
                session.permanent = True
                generate_csrf_token()
                return redirect(url_for("dashboard"))
            flash(msg, "error")
        elif action == "resend":
            pending = session.get("otp_pending")
            if pending:
                ok, msg, demo_code = system.send_email_otp(pending)
                flash(msg, "success" if ok else "error")
                if demo_code:
                    flash(f"🧪 Demo OTP: {demo_code}", "success")
    otp_pending = session.get("otp_pending")
    return render_template("login_otp.html", otp_pending=otp_pending)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        check_csrf()
        username = request.form["username"]
        password = request.form["password"]
        ok, msg = system.register(username, password, "viewer")
        flash(msg, "success" if ok else "error")
        if ok:
            return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ─── Dashboard ───────────────────────────────────────────────────────────────

@app.route("/dashboard")
@require_login
def dashboard():
    files   = system.list_files(current_user())
    logs    = system.get_logs(limit=10)
    profile = system.get_profile(current_user())
    return render_template("dashboard.html",
                           files=files,
                           logs=logs,
                           user=profile,
                           username=current_user())

# ─── File Operations ─────────────────────────────────────────────────────────

@app.route("/upload", methods=["POST"])
@require_login
def upload():
    check_csrf()
    f = request.files.get("file")
    if not f or f.filename == "":
        flash("Fayl tanlanmadi", "error")
        return redirect(url_for("dashboard"))
    ok, msg = system.upload_file(current_user(), f.filename, f.read())
    flash(msg, "success" if ok else "error")
    return redirect(url_for("dashboard"))

@app.route("/download/<filename>")
@require_login
def download(filename):
    ok, msg, data = system.download_file(current_user(), filename)
    if not ok:
        flash(msg, "error")
        return redirect(url_for("dashboard"))
    import io
    return send_file(io.BytesIO(data), download_name=filename, as_attachment=True)

@app.route("/delete/<filename>", methods=["POST"])
@require_login
def delete(filename):
    check_csrf()
    ok, msg = system.delete_file(current_user(), filename)
    flash(msg, "success" if ok else "error")
    return redirect(url_for("dashboard"))

# ─── Permissions ─────────────────────────────────────────────────────────────

@app.route("/permissions/<filename>")
@require_login
def permissions(filename):
    acl      = system.get_acl(current_user(), filename)
    all_users = system.list_users()
    users    = [u["username"] for u in all_users if u["username"] != current_user()]
    return render_template("permissions.html",
                           filename=filename,
                           acl=acl,
                           users=users,
                           username=current_user())

@app.route("/share/<filename>", methods=["POST"])
@require_login
def share(filename):
    check_csrf()
    target     = request.form["target_user"]
    permission = request.form["permission"]
    ok, msg    = system.share_file(current_user(), filename, target, permission)
    flash(msg, "success" if ok else "error")
    return redirect(url_for("permissions", filename=filename))

@app.route("/revoke/<filename>/<target>", methods=["POST"])
@require_login
def revoke(filename, target):
    check_csrf()
    ok, msg = system.revoke_access(current_user(), filename, target)
    flash(msg, "success" if ok else "error")
    return redirect(url_for("permissions", filename=filename))

# ─── Logs ────────────────────────────────────────────────────────────────────

@app.route("/logs")
@require_login
def logs():
    profile = system.get_profile(current_user())
    if profile.get("role") != "admin":
        flash("Faqat admin uchun", "error")
        return redirect(url_for("dashboard"))
    all_logs = system.get_logs(limit=100)
    return render_template("logs.html", logs=all_logs, username=current_user())

# ─── Search ──────────────────────────────────────────────────────────────────

@app.route("/search")
@require_login
def search():
    query   = request.args.get("q", "")
    results = system.search_files(current_user(), query)
    return render_template("search.html", results=results, query=query, username=current_user())

# ─── Stats ───────────────────────────────────────────────────────────────────

@app.route("/stats")
@require_login
def stats():
    data = system.get_stats()
    return render_template("stats.html", stats=data, username=current_user())

# ─── Share Links ─────────────────────────────────────────────────────────────

@app.route("/links")
@require_login
def links():
    all_links = system.list_links(current_user())
    return render_template("links.html", links=all_links, username=current_user())

@app.route("/create_link/<filename>", methods=["POST"])
@require_login
def create_link(filename):
    check_csrf()
    hours    = int(request.form.get("hours", 24))
    ok, msg, token = system.create_share_link(current_user(), filename, hours)
    if ok:
        flash(f"✅ Havola yaratildi! Token: {token}", "success")
    else:
        flash(msg, "error")
    return redirect(url_for("links"))

@app.route("/delete_link/<token>", methods=["POST"])
@require_login
def delete_link(token):
    check_csrf()
    ok, msg = system.delete_link(current_user(), token)
    flash(msg, "success" if ok else "error")
    return redirect(url_for("links"))

@app.route("/shared/<token>")
def shared_download(token):
    row = system.get_share_link(token)
    if not row:
        return render_template("link_error.html", message="Havola topilmadi yoki muddati tugagan"), 404
    filename = row["filename"]
    # Admin nomidan yuklab berish
    ok, msg, data = system.download_file("admin", filename)
    if not ok:
        return render_template("link_error.html", message=msg), 404
    import io
    return send_file(io.BytesIO(data), download_name=filename, as_attachment=True)

# ─── Profile ─────────────────────────────────────────────────────────────────

@app.route("/profile", methods=["GET", "POST"])
@require_login
def profile():
    if request.method == "POST":
        check_csrf()
        action = request.form.get("action")
        if action == "update_profile":
            display_name = request.form.get("display_name", "")
            email        = request.form.get("email", "")
            ok, msg = system.update_profile(current_user(), display_name, email)
            flash(msg, "success" if ok else "error")
        elif action == "change_password":
            old_pw  = request.form.get("old_password", "")
            new_pw  = request.form.get("new_password", "")
            confirm = request.form.get("confirm_password", "")
            if new_pw != confirm:
                flash("Yangi parollar mos kelmadi", "error")
            else:
                ok, msg = system.change_password(current_user(), old_pw, new_pw)
                flash(msg, "success" if ok else "error")
        return redirect(url_for("profile"))

    profile_data = system.get_profile(current_user())
    totp_enabled = profile_data.get("totp_enabled", False)
    return render_template("profile.html",
                           profile=profile_data,
                           username=current_user(),
                           totp_enabled=totp_enabled)

# ─── 2FA Setup ───────────────────────────────────────────────────────────────

@app.route("/2fa/setup")
@require_login
def setup_2fa():
    ok, msg, otpauth_url = system.setup_2fa(current_user())
    if not ok:
        flash(msg, "error")
        return redirect(url_for("profile"))
    import urllib.parse
    qr_img = f"https://api.qrserver.com/v1/create-qr-code/?size=200x200&data={urllib.parse.quote(otpauth_url)}"
    # pending secret
    from database import fetchone
    u = fetchone("SELECT totp_pending FROM users WHERE username=%s", (current_user(),))
    secret = (u or {}).get("totp_pending", "")
    return render_template("2fa_setup.html",
                           qr_img=qr_img,
                           otpauth_url=otpauth_url,
                           secret=secret,
                           username=current_user())

@app.route("/2fa/confirm", methods=["POST"])
@require_login
def confirm_2fa():
    check_csrf()
    code = request.form.get("code", "").strip()
    ok, msg = system.confirm_2fa(current_user(), code)
    flash(msg, "success" if ok else "error")
    return redirect(url_for("profile") if ok else url_for("setup_2fa"))

@app.route("/2fa/disable", methods=["POST"])
@require_login
def disable_2fa():
    check_csrf()
    code = request.form.get("code", "").strip()
    ok, msg = system.disable_2fa(current_user(), code)
    flash(msg, "success" if ok else "error")
    return redirect(url_for("profile"))

# ─── Admin ───────────────────────────────────────────────────────────────────

@app.route("/admin/users")
@require_login
def admin_users():
    profile = system.get_profile(current_user())
    if profile.get("role") != "admin":
        flash("Faqat admin uchun", "error")
        return redirect(url_for("dashboard"))
    all_users = system.list_users()
    return render_template("admin_users.html", users=all_users, username=current_user())

@app.route("/admin/change_password", methods=["POST"])
@require_login
def admin_change_password():
    check_csrf()
    target  = request.form.get("target_user")
    new_pw  = request.form.get("new_password")
    confirm = request.form.get("confirm_password")
    if new_pw != confirm:
        flash("Parollar mos kelmadi", "error")
    else:
        ok, msg = system.admin_change_password(current_user(), target, new_pw)
        flash(msg, "success" if ok else "error")
    return redirect(url_for("admin_users"))

@app.route("/admin/change_role", methods=["POST"])
@require_login
def admin_change_role():
    check_csrf()
    target   = request.form.get("target_user")
    new_role = request.form.get("new_role")
    ok, msg  = system.change_role(current_user(), target, new_role)
    flash(msg, "success" if ok else "error")
    return redirect(url_for("admin_users"))

# ─── API ─────────────────────────────────────────────────────────────────────

@app.route("/api/files")
@require_login
def api_files():
    return jsonify(system.list_files(current_user()))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)