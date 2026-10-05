"""
Automated end-to-end test for ZeroGate.
Run:  python test_app.py
Uses a separate temporary database, so your real users and logs are not touched.
"""
import os
import re
import tempfile

import pyotp

import app as zerogate

zerogate.DB_PATH = os.path.join(tempfile.mkdtemp(), "test.db")
zerogate.init_db()
client = zerogate.app.test_client()

passed = failed = 0


def check(name, condition):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        print(f"  FAIL  {name}")


def login(username, password, **demo):
    return client.post("/login", data={"username": username, "password": password, "demo_hour": "11", **demo})


print("\nZeroGate tests\n")

# TC1 register
r = client.post("/register", data={"username": "ravi", "password": "1234", "role": "employee"})
secret = re.search(r"<code>(\w+)</code>", r.text).group(1)
check("TC1  Register shows QR code", "<svg" in r.text)

# TC2 first login enrolls device + IP
r = login("ravi", "1234")
check("TC2  First login is allowed", r.headers.get("Location") == "/dashboard")

# TC8 / TC9 role policy
check("TC8  Employee can open HR", client.get("/resource/hr").status_code == 200)
check("TC9  Employee blocked from Finance", "Access blocked" in client.get("/resource/finance").text)
client.get("/logout")

# TC3 normal repeat login
r = login("ravi", "1234")
check("TC3  Normal repeat login is allowed", r.headers.get("Location") == "/dashboard")
client.get("/logout")

# TC4 wrong password
r = login("ravi", "wrong")
check("TC4  Wrong password is rejected", "Invalid username or password" in r.text)

# TC5 new IP -> OTP
r = login("ravi", "1234", demo_ip="45.33.12.9")
check("TC5  New IP asks for OTP", r.headers.get("Location") == "/otp")

# TC6 wrong then correct OTP
r = client.post("/otp", data={"code": "000000"})
check("TC6a Wrong OTP is rejected", "Wrong OTP" in r.text)
r = client.post("/otp", data={"code": pyotp.TOTP(secret).now()})
check("TC6b Correct OTP is allowed", r.headers.get("Location") == "/dashboard")
client.get("/logout")

# TC7 attack: 3 failed logins + new IP + new device + 3 AM
for _ in range(3):
    login("ravi", "bad")
r = login("ravi", "1234", demo_ip="9.9.9.9", demo_device="Hacker-Laptop", demo_hour="3")
check("TC7  Stolen-password attack is blocked", "Access blocked" in r.text)

# TC10 admin step-up MFA for Finance
r = client.post("/register", data={"username": "boss", "password": "1234", "role": "admin"})
boss_secret = re.search(r"<code>(\w+)</code>", r.text).group(1)
login("boss", "1234")
r = client.get("/resource/finance")
check("TC10 Admin must enter OTP before Finance", r.headers.get("Location") == "/otp")
client.post("/otp", data={"code": pyotp.TOTP(boss_secret).now()})
check("TC11 Admin opens Finance after OTP", client.get("/resource/finance").status_code == 200)

# TC12 logs
r = client.get("/admin/logs")
check("TC12 Admin can see security logs", r.status_code == 200 and "BLOCK" in r.text)

# TC13 duplicate username
r = client.post("/register", data={"username": "ravi", "password": "1234", "role": "employee"})
check("TC13 Duplicate username is rejected", "already exists" in r.text)

print(f"\nResult: {passed} passed, {failed} failed\n")
raise SystemExit(1 if failed else 0)
