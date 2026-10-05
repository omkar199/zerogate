"""
ZeroGate - Risk-Based Login System (Zero Trust mini project)

Every login is scored for risk (IP, device, time, failed attempts):
  score 0-29  -> ALLOW
  score 30-70 -> ask for OTP (Google Authenticator)
  score 71+   -> BLOCK
Every request to a protected resource is checked again (role + MFA),
so a logged-in user cannot freely move to other resources.
"""
import hashlib
import io
import os
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

import pyotp
import qrcode
import qrcode.image.svg
from flask import Flask, g, redirect, render_template, request, session, url_for, flash
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

from risk import calculate_risk, decide

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)  # real client IP behind hosting proxy
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")
DB_PATH = os.path.join(os.path.dirname(__file__), "zerogate.db")

# Which roles can open which resource, and whether OTP is required (sensitive data)
RESOURCES = {
    "hr": {"title": "HR Portal", "roles": ["admin", "manager", "employee"], "needs_mfa": False},
    "finance": {"title": "Finance Reports", "roles": ["admin", "manager"], "needs_mfa": True},
    "admin": {"title": "Admin Settings", "roles": ["admin"], "needs_mfa": True},
}


# ---------------- Database ----------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            totp_secret TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS known_ips (user_id INTEGER, ip TEXT, UNIQUE(user_id, ip));
        CREATE TABLE IF NOT EXISTS known_devices (user_id INTEGER, device TEXT, UNIQUE(user_id, device));
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time TEXT, username TEXT, ip TEXT, device TEXT,
            action TEXT, score INTEGER, reasons TEXT, decision TEXT
        );
    """)
    db.commit()
    db.close()


def add_log(username, ip, device, action, score, reasons, decision):
    db = get_db()
    db.execute(
        "INSERT INTO logs (time, username, ip, device, action, score, reasons, decision) VALUES (?,?,?,?,?,?,?,?)",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), username, ip, device, action, score, "; ".join(reasons), decision),
    )
    db.commit()


def remember_context(user_id, ip, device):
    db = get_db()
    db.execute("INSERT OR IGNORE INTO known_ips VALUES (?, ?)", (user_id, ip))
    db.execute("INSERT OR IGNORE INTO known_devices VALUES (?, ?)", (user_id, device))
    db.commit()


# ---------------- Request context (IP, device, hour) ----------------
def get_context(form=None):
    """Real IP/device/hour, or the 'demo simulation' values from the login form."""
    form = form or {}
    ip = form.get("demo_ip") or request.remote_addr
    device_src = form.get("demo_device") or request.headers.get("User-Agent", "")
    device = hashlib.sha256(device_src.encode()).hexdigest()[:12]
    hour = int(form["demo_hour"]) if form.get("demo_hour") else datetime.now().hour
    return ip, device, hour


# ---------------- Helpers ----------------
def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


def current_user():
    return get_db().execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()


def finish_login(user, ip, device, mfa_verified):
    session.clear()
    session["user_id"] = user["id"]
    session["mfa_verified"] = mfa_verified
    remember_context(user["id"], ip, device)


# ---------------- Routes ----------------
@app.route("/")
def index():
    return redirect(url_for("dashboard") if "user_id" in session else url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        role = request.form["role"]
        if not username or len(password) < 4 or role not in ("admin", "manager", "employee"):
            flash("Enter a username, a password of 4+ characters and a valid role.")
            return render_template("register.html")

        secret = pyotp.random_base32()
        try:
            db = get_db()
            db.execute(
                "INSERT INTO users (username, password_hash, role, totp_secret) VALUES (?,?,?,?)",
                (username, generate_password_hash(password), role, secret),
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("Username already exists.")
            return render_template("register.html")

        # QR code for Google Authenticator (SVG, no extra image library needed)
        uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="ZeroGate")
        buf = io.BytesIO()
        qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage).save(buf)
        return render_template("qr.html", qr_svg=buf.getvalue().decode(), secret=secret, username=username)

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        ip, device, hour = get_context(request.form)
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if not user or not check_password_hash(user["password_hash"], password):
            add_log(username, ip, device, "login", 0, ["Wrong username or password"], "FAILED")
            flash("Invalid username or password.")
            return render_template("login.html")

        # Collect risk signals
        is_new_ip = not db.execute("SELECT 1 FROM known_ips WHERE user_id=? AND ip=?", (user["id"], ip)).fetchone()
        is_new_device = not db.execute(
            "SELECT 1 FROM known_devices WHERE user_id=? AND device=?", (user["id"], device)).fetchone()
        first_login = not db.execute("SELECT 1 FROM known_ips WHERE user_id=?", (user["id"],)).fetchone()
        since = (datetime.now() - timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")
        failed = db.execute(
            "SELECT COUNT(*) FROM logs WHERE username=? AND decision='FAILED' AND time>=?", (username, since)
        ).fetchone()[0]

        if first_login:
            # First successful login registers this device and IP as trusted (enrollment)
            score, reasons = 0, ["First login - device and IP enrolled as trusted"]
        else:
            score, reasons = calculate_risk(is_new_ip, is_new_device, hour, failed)
        decision = decide(score)
        add_log(username, ip, device, "login", score, reasons, decision)

        if decision == "ALLOW":
            finish_login(user, ip, device, mfa_verified=False)
            flash(f"Low risk ({score}/100) - access granted.")
            return redirect(url_for("dashboard"))
        if decision == "OTP":
            session.clear()
            session["pending"] = {"user_id": user["id"], "ip": ip, "device": device, "score": score}
            flash(f"Medium risk ({score}/100): " + ", ".join(reasons) + ". Please verify with OTP.")
            return redirect(url_for("otp"))
        return render_template("blocked.html", score=score, reasons=reasons)

    return render_template("login.html")


@app.route("/otp", methods=["GET", "POST"])
def otp():
    """Step-up MFA: used after a medium-risk login or before opening a sensitive resource."""
    pending = session.get("pending")
    step_up_user = session.get("user_id")
    if not pending and not step_up_user:
        return redirect(url_for("login"))

    user_id = pending["user_id"] if pending else step_up_user
    user = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    if request.method == "POST":
        ip, device = (pending["ip"], pending["device"]) if pending else get_context()[:2]
        if pyotp.TOTP(user["totp_secret"]).verify(request.form["code"].strip(), valid_window=1):
            add_log(user["username"], ip, device, "otp", 0, ["OTP correct"], "ALLOW")
            next_url = session.get("next")
            finish_login(user, ip, device, mfa_verified=True)
            flash("OTP verified.")
            return redirect(next_url or url_for("dashboard"))
        add_log(user["username"], ip, device, "otp", 0, ["Wrong OTP"], "FAILED")
        flash("Wrong OTP, try again.")

    return render_template("otp.html", username=user["username"])


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user(), resources=RESOURCES,
                           mfa=session.get("mfa_verified"))


@app.route("/resource/<name>")
@login_required
def resource(name):
    """Zero Trust check on EVERY request: role policy + MFA for sensitive data."""
    res = RESOURCES.get(name)
    if not res:
        return redirect(url_for("dashboard"))
    user = current_user()
    ip, device, _ = get_context()

    if user["role"] not in res["roles"]:
        add_log(user["username"], ip, device, f"open:{name}", 100,
                [f"Role '{user['role']}' not allowed"], "BLOCK")
        return render_template("blocked.html", score=100,
                               reasons=[f"Your role '{user['role']}' cannot access {res['title']} (least privilege)."])

    if res["needs_mfa"] and not session.get("mfa_verified"):
        add_log(user["username"], ip, device, f"open:{name}", 50, ["Sensitive resource needs OTP"], "OTP")
        session["next"] = url_for("resource", name=name)
        flash(f"{res['title']} is sensitive. Verify OTP to continue.")
        return redirect(url_for("otp"))

    add_log(user["username"], ip, device, f"open:{name}", 0, ["Policy passed"], "ALLOW")
    return render_template("resource.html", res=res, user=user)


@app.route("/admin/logs")
@login_required
def admin_logs():
    user = current_user()
    if user["role"] != "admin":
        return redirect(url_for("resource", name="admin"))
    db = get_db()
    logs = db.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 200").fetchall()
    stats = {row["decision"]: row["c"] for row in
             db.execute("SELECT decision, COUNT(*) c FROM logs GROUP BY decision").fetchall()}
    return render_template("logs.html", logs=logs, stats=stats)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


init_db()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5001)))
