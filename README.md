# ZeroGate: Risk-Based Login System (Zero Trust)

A login system that **does not trust anyone by default**. Every login gets a risk score from its
IP address, device, time and failed attempts, and every page request is checked again.

| Risk score | Decision |
|---|---|
| 0 - 29 | ✅ ALLOW |
| 30 - 70 | 🔐 Ask for OTP (Google Authenticator) |
| 71 - 100 | ⛔ BLOCK |

| Risk signal | Points |
|---|---|
| New IP address | +30 |
| Unknown device / browser | +25 |
| Login between 12 AM and 6 AM | +20 |
| 3+ failed logins in last 15 min | +25 |

| Page | Who can open | OTP needed |
|---|---|---|
| HR Portal | employee, manager, admin | No |
| Finance Reports | manager, admin | Yes |
| Admin Settings | admin | Yes |
| Security Logs (`/admin/logs`) | admin | No |

---

## 1. Requirements

| What | Version | Cost |
|---|---|---|
| Python | 3.10 or newer (check with `python3 --version`) | Free |
| pip packages | `flask`, `pyotp`, `qrcode`, `gunicorn` (in `requirements.txt`) | Free |
| Phone app | **Google Authenticator** or Microsoft Authenticator | Free |
| Browser | Chrome / Firefox / Edge / Safari | Free |

No database setup is needed. SQLite is built into Python, and the file `zerogate.db` is created automatically on first run.

## 2. Environment variables

**Both are optional.** The app runs without setting anything.

| Variable | Default | What it does |
|---|---|---|
| `SECRET_KEY` | `dev-secret-change-me` | Signs login sessions (cookies). Set a long random value when you put the app online. |
| `PORT` | `5001` | Port the app listens on. Render sets this automatically. |

To set them (optional):

```bash
# macOS / Linux
export SECRET_KEY="any-long-random-text-here"
export PORT=5001

# Windows (PowerShell)
$env:SECRET_KEY="any-long-random-text-here"
```

## 3. How to run

### macOS / Linux

```bash
cd zerogate-final
python3 -m venv venv              # one time: create virtual environment
source venv/bin/activate          # every time: activate it
pip install -r requirements.txt   # one time: install packages
python app.py                     # start the app
```

### Windows

```bash
cd zerogate-final
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:5001** in your browser. Press `Ctrl + C` in the terminal to stop.

> **"Invalid username or password" on first login?** That is normal. The database starts empty,
> so click **Register** and create a user first.

> **Port already in use?** Run on another port: `PORT=5050 python app.py`
> (on macOS, port 5000 is taken by AirPlay, which is why the default is 5001).

## 4. First-time setup (2 minutes)

1. Click **Register**. Create `ravi`, password `1234`, role **Employee**.
2. A QR code appears. Open **Google Authenticator** on your phone → **+** → **Scan a QR code** → scan it.
   (No camera? Choose **Enter a setup key** and type the key shown under the QR code.)
3. Click **Register** again. Create `boss`, password `1234`, role **Admin**, and scan that QR code too.
4. Log in once as each user. The **first login** saves that browser and IP as trusted.

## 5. Automated test (checks everything in 5 seconds)

```bash
source venv/bin/activate     # Windows: venv\Scripts\activate
python test_app.py
```

Expected output ends with: `Result: 14 passed, 0 failed`

It uses a temporary database, so your real users are not affected.

## 6. Manual testing: every feature

Do these in order after the first-time setup. To try a scenario, open **"Demo mode: simulate an attack"**
on the login page. It lets you fake an IP, device or hour on one laptop.

| # | Test | Steps | Expected result |
|---|---|---|---|
| 1 | Normal login | Logout → log in as `ravi` / `1234`, demo mode empty | ✅ Dashboard: "Low risk (0/100)" |
| 2 | Wrong password | Log in as `ravi` with password `abc` | "Invalid username or password" |
| 3 | New IP → OTP | Log in as `ravi`, demo **Fake IP** = `45.33.12.9` | 🔐 OTP page: "Medium risk (30/100): New IP address" |
| 4 | Wrong OTP | On OTP page enter `000000` | "Wrong OTP, try again" |
| 5 | Correct OTP | Enter the 6-digit code from Google Authenticator | ✅ Dashboard: "OTP verified" |
| 6 | New device at night → OTP | Logout → log in, **Fake device** = `Hacker-Laptop`, **Fake hour** = `3` | 🔐 OTP page, score 45 (device 25 + night 20) |
| 7 | New IP + new device + night | Logout → **Fake IP** `8.8.8.8`, **Fake device** `Phone-X`, **Fake hour** `3` | ⛔ Blocked, score 75 (30 + 25 + 20) |
| 8 | Stolen-password attack | Enter wrong password **3 times**, then correct password with Fake IP `9.9.9.9`, Fake device `Hacker`, Fake hour `3` | ⛔ "Access blocked", score 100 |
| 9 | Least privilege | Log in as `ravi` → click **HR Portal** | ✅ Access granted |
| 10 | Lateral movement blocked | As `ravi` click **Finance Reports** or **Admin Settings** | ⛔ "Your role 'employee' cannot access..." |
| 11 | Step-up MFA | Log in as `boss` (normal) → click **Finance Reports** | 🔐 Asks OTP first, then ✅ opens |
| 12 | Security logs | As `boss` click **Logs** in top menu | Table of every attempt with score, reasons, decision + counts |
| 13 | Employee cannot see logs | As `ravi` click **Logs** | ⛔ Blocked (redirected to Admin Settings check) |
| 14 | Duplicate user | Register `ravi` again | "Username already exists" |

## 7. Reset everything

Stop the app, delete the database and start again:

```bash
rm zerogate.db        # Windows: del zerogate.db
python app.py
```

Note: after a reset, remove the old ZeroGate entries in Google Authenticator and scan the new QR codes.

## 8. Put it online for free (optional)

1. Push this folder to a GitHub repository.
2. On https://render.com → **New → Blueprint** → choose the repository. It reads `render.yaml`
   (free plan, `gunicorn app:app`, random `SECRET_KEY`).
3. You get a link like `https://zerogate.onrender.com`.

On the free plan the app sleeps after 15 minutes idle (the first load takes about 30 seconds), and data resets when it restarts.
Register the demo users again before presenting.

## 9. Project files

| File | What it contains |
|---|---|
| `app.py` | Routes: register, login, OTP, dashboard, resources, logs, access policy |
| `risk.py` | Risk scoring rules and ALLOW / OTP / BLOCK decision |
| `templates/` | HTML pages (login, register, QR, OTP, dashboard, blocked, logs) |
| `test_app.py` | Automated test of all scenarios |
| `requirements.txt` | Python packages |
| `render.yaml` | Free online deployment config |
| `zerogate.db` | Created automatically: users, trusted IPs/devices, logs |

## 10. Troubleshooting

| Problem | Fix |
|---|---|
| `command not found: python3` | Install Python from https://python.org (tick "Add to PATH" on Windows) |
| `ModuleNotFoundError: flask` | Activate venv (`source venv/bin/activate`) and run `pip install -r requirements.txt` |
| OTP always wrong | Phone time must be automatic. Settings → Date & Time → Set automatically |
| Lost the QR code | Delete `zerogate.db` and register again (see Reset) |
| Port in use | `PORT=5050 python app.py` |
