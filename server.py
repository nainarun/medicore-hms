#!/usr/bin/env python3
"""
MediCore HMS - Python Backend
Pure stdlib: http.server + sqlite3 + hashlib + json
Usage: python3 server.py
Runs on http://localhost:8000
"""

import json
import sqlite3
import hashlib
import hmac
import base64
import time
import uuid
import re
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
PORT = int(os.environ.get("PORT", 8000))
DB_PATH = os.path.join(os.path.dirname(__file__), "medicore.db")
JWT_SECRET = "medicore-super-secret-jwt-key-2026"
JWT_EXPIRY = 3600  # 1 hour


# ─────────────────────────────────────────────
# SIMPLE JWT (HMAC-SHA256)
# ─────────────────────────────────────────────
def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * (padding % 4))

def create_token(payload: dict) -> str:
    header = b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload["exp"] = int(time.time()) + JWT_EXPIRY
    body = b64url_encode(json.dumps(payload).encode())
    sig_input = f"{header}.{body}".encode()
    sig = hmac.new(JWT_SECRET.encode(), sig_input, hashlib.sha256).digest()
    return f"{header}.{body}.{b64url_encode(sig)}"

def verify_token(token: str) -> dict | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header, body, sig = parts
        sig_input = f"{header}.{body}".encode()
        expected = hmac.new(JWT_SECRET.encode(), sig_input, hashlib.sha256).digest()
        if not hmac.compare_digest(b64url_encode(expected), sig):
            return None
        payload = json.loads(b64url_decode(body))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


# ─────────────────────────────────────────────
# DATABASE SETUP
# ─────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()

    c.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin','doctor','patient')),
        created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS patients (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        dob TEXT,
        gender TEXT,
        blood_type TEXT,
        phone TEXT,
        address TEXT,
        medical_history TEXT,
        status TEXT DEFAULT 'active',
        created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS doctors (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        specialty TEXT,
        license_no TEXT UNIQUE,
        email TEXT,
        phone TEXT,
        availability TEXT DEFAULT 'Full Time',
        status TEXT DEFAULT 'active',
        rating REAL DEFAULT 4.5,
        patient_count INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS appointments (
        id TEXT PRIMARY KEY,
        patient_id TEXT,
        patient_name TEXT,
        doctor_id TEXT,
        doctor_name TEXT,
        department TEXT,
        room TEXT,
        appointment_date TEXT,
        appointment_time TEXT,
        status TEXT DEFAULT 'scheduled' CHECK(status IN ('scheduled','completed','cancelled')),
        notes TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(patient_id) REFERENCES patients(id),
        FOREIGN KEY(doctor_id) REFERENCES doctors(id)
    );

    CREATE TABLE IF NOT EXISTS prescriptions (
        id TEXT PRIMARY KEY,
        patient_id TEXT,
        patient_name TEXT,
        doctor_id TEXT,
        doctor_name TEXT,
        medication TEXT NOT NULL,
        dosage TEXT,
        duration TEXT,
        refills INTEGER DEFAULT 0,
        instructions TEXT,
        status TEXT DEFAULT 'active' CHECK(status IN ('active','completed','cancelled')),
        issued_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(patient_id) REFERENCES patients(id),
        FOREIGN KEY(doctor_id) REFERENCES doctors(id)
    );

    CREATE TABLE IF NOT EXISTS invoices (
        id TEXT PRIMARY KEY,
        patient_id TEXT,
        patient_name TEXT,
        service TEXT,
        amount REAL NOT NULL,
        invoice_date TEXT DEFAULT (date('now')),
        status TEXT DEFAULT 'pending' CHECK(status IN ('paid','pending','overdue')),
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(patient_id) REFERENCES patients(id)
    );

    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        level TEXT,
        message TEXT,
        endpoint TEXT,
        user_email TEXT,
        created_at TEXT DEFAULT (datetime('now', 'localtime'))
    );
    """)

    # Seed users
    users = [
        (str(uuid.uuid4()), "Dr. Admin",      "admin@medicore.com",   hash_password("admin123"),   "admin"),
        (str(uuid.uuid4()), "Dr. Emily Chen", "doctor@medicore.com",  hash_password("doctor123"),  "doctor"),
        (str(uuid.uuid4()), "Sarah Johnson",  "patient@medicore.com", hash_password("patient123"), "patient"),
    ]
    for u in users:
        c.execute("INSERT OR IGNORE INTO users (id,name,email,password_hash,role) VALUES (?,?,?,?,?)", u)

    # Seed patients
    patients = [
        ("P001","Sarah Johnson","1990-03-14","Female","A+","555-0101","123 Oak St","Hypertension","active"),
        ("P002","Michael Torres","1972-07-22","Male","O+","555-0102","456 Elm Ave","Diabetes T2","active"),
        ("P003","Linda Zhao","1995-11-05","Female","B-","555-0103","789 Pine Rd","None","active"),
        ("P004","David Osei","1983-01-30","Male","AB+","555-0104","321 Maple Dr","Asthma","inactive"),
        ("P005","Maria Garcia","2001-06-18","Female","O-","555-0105","654 Cedar Ln","None","active"),
        ("P006","Thomas Wu","1968-09-12","Male","A-","555-0106","987 Birch Blvd","Hypertension, Diabetes","active"),
        ("P007","Clara Osei","1979-04-25","Female","B+","555-0107","111 Walnut St","Respiratory","active"),
        ("P008","Emily Wu","1997-12-03","Female","AB-","555-0108","222 Spruce Ave","Infection","active"),
    ]
    for p in patients:
        c.execute("INSERT OR IGNORE INTO patients (id,name,dob,gender,blood_type,phone,address,medical_history,status) VALUES (?,?,?,?,?,?,?,?,?)", p)

    # Seed doctors
    doctors = [
        ("D001","Dr. Emily Chen","General Medicine","MD-00142","emily.chen@medicore.com","555-1001","Full Time","active",4.9,142),
        ("D002","Dr. James Park","Cardiology","MD-00205","james.park@medicore.com","555-1002","Full Time","active",4.8,128),
        ("D003","Dr. Rachel Kim","Orthopedics","MD-00318","rachel.kim@medicore.com","555-1003","Full Time","active",4.7,97),
        ("D004","Dr. Natasha Obi","Pediatrics","MD-00421","natasha.obi@medicore.com","555-1004","Part Time","active",4.9,84),
        ("D005","Dr. Alan Carter","Neurology","MD-00532","alan.carter@medicore.com","555-1005","Full Time","on_leave",4.6,61),
    ]
    for d in doctors:
        c.execute("INSERT OR IGNORE INTO doctors (id,name,specialty,license_no,email,phone,availability,status,rating,patient_count) VALUES (?,?,?,?,?,?,?,?,?,?)", d)

    # Seed appointments
    appts = [
        ("A001","P001","Sarah Johnson","D001","Dr. Emily Chen","General","Room 201","2026-02-26","09:00","completed","Annual checkup"),
        ("A002","P002","Michael Torres","D002","Dr. James Park","Cardiology","Room 305","2026-02-26","10:30","completed","ECG follow-up"),
        ("A003","P003","Linda Zhao","D003","Dr. Rachel Kim","Orthopedics","Room 112","2026-02-27","13:00","scheduled","Knee pain evaluation"),
        ("A004","P004","David Osei","D004","Dr. Natasha Obi","Pediatrics","Room 408","2026-02-27","15:15","scheduled","Child checkup"),
        ("A005","P005","Maria Garcia","D001","Dr. Emily Chen","General","Room 201","2026-02-28","11:00","scheduled","New patient intake"),
        ("A006","P006","Thomas Wu","D001","Dr. Emily Chen","General","Room 201","2026-03-01","14:00","scheduled","Lab results review"),
        ("A007","P002","Michael Torres","D002","Dr. James Park","Cardiology","Room 305","2026-02-20","09:30","cancelled","Rescheduled by patient"),
        ("A008","P007","Clara Osei","D001","Dr. Emily Chen","General","Room 201","2026-02-25","15:30","completed","Respiratory check"),
    ]
    for a in appts:
        c.execute("INSERT OR IGNORE INTO appointments (id,patient_id,patient_name,doctor_id,doctor_name,department,room,appointment_date,appointment_time,status,notes) VALUES (?,?,?,?,?,?,?,?,?,?,?)", a)

    # Seed prescriptions
    rxs = [
        ("RX001","P001","Sarah Johnson","D001","Dr. Emily Chen","Lisinopril 10mg","1 tablet daily","90 days",3,"Take in morning","active"),
        ("RX002","P002","Michael Torres","D002","Dr. James Park","Metformin 500mg","1 tablet 2x daily","60 days",2,"Take with meals","active"),
        ("RX003","P003","Linda Zhao","D003","Dr. Rachel Kim","Ibuprofen 400mg","1 tablet 3x daily","14 days",0,"Take with food","active"),
        ("RX004","P006","Thomas Wu","D001","Dr. Emily Chen","Atorvastatin 20mg","1 tablet nightly","90 days",3,"Avoid grapefruit","active"),
        ("RX005","P007","Clara Osei","D001","Dr. Emily Chen","Salbutamol Inhaler","2 puffs as needed","30 days",1,"Shake before use","active"),
        ("RX006","P008","Emily Wu","D001","Dr. Emily Chen","Amoxicillin 500mg","1 capsule 3x daily","7 days",0,"Complete full course","completed"),
    ]
    for r in rxs:
        c.execute("INSERT OR IGNORE INTO prescriptions (id,patient_id,patient_name,doctor_id,doctor_name,medication,dosage,duration,refills,instructions,status) VALUES (?,?,?,?,?,?,?,?,?,?,?)", r)

    # Seed invoices
    invs = [
        ("INV-4521","P001","Sarah Johnson","General Checkup",340.00,"2026-02-26","paid"),
        ("INV-4522","P002","Michael Torres","Cardiology Consultation",820.00,"2026-02-20","pending"),
        ("INV-4523","P003","Linda Zhao","Orthopedic Evaluation",215.50,"2026-02-18","paid"),
        ("INV-4524","P004","David Osei","Pediatrics Visit",455.00,"2026-01-15","overdue"),
        ("INV-4525","P005","Maria Garcia","New Patient Registration",150.00,"2026-02-25","paid"),
        ("INV-4526","P006","Thomas Wu","Lab Tests",380.00,"2026-02-22","pending"),
        ("INV-4527","P007","Clara Osei","Respiratory Therapy",290.00,"2026-02-10","overdue"),
        ("INV-4528","P008","Emily Wu","Infection Treatment",175.00,"2026-02-24","paid"),
    ]
    for i in invs:
        c.execute("INSERT OR IGNORE INTO invoices (id,patient_id,patient_name,service,amount,invoice_date,status) VALUES (?,?,?,?,?,?,?)", i)

    conn.commit()
    conn.close()
    print(f"[DB] Initialized: {DB_PATH}")


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────
def log_request(conn, level, message, endpoint="", user_email=""):
    conn.execute(
        "INSERT INTO logs (level,message,endpoint,user_email) VALUES (?,?,?,?)",
        (level, message, endpoint, user_email)
    )
    conn.commit()

def rows_to_list(rows):
    return [dict(r) for r in rows]

def json_response(handler, data, status=200):
    body = json.dumps(data, default=str).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", len(body))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
    handler.send_header("Access-Control-Allow-Headers", "Authorization,Content-Type")
    handler.end_headers()
    handler.wfile.write(body)

def error_response(handler, msg, status=400):
    json_response(handler, {"error": msg}, status)

def get_auth_user(handler):
    auth = handler.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return verify_token(auth[7:])
    return None

def read_body(handler):
    length = int(handler.headers.get("Content-Length", 0))
    if length:
        return json.loads(handler.rfile.read(length))
    return {}


# ─────────────────────────────────────────────
# REQUEST HANDLER
# ─────────────────────────────────────────────
class HMSHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass  # Suppress default access log (we use our own)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization,Content-Type")
        self.end_headers()

    def route(self):
        parsed = urlparse(self.path)
        self.url_path = parsed.path.rstrip("/")
        self.query = parse_qs(parsed.query)
        self.path_parts = [p for p in self.url_path.split("/") if p]

    def match(self, method, pattern):
        if self.command != method:
            return False, {}
        parts = [p for p in pattern.split("/") if p]
        if len(parts) != len(self.path_parts):
            return False, {}
        params = {}
        for pp, rp in zip(parts, self.path_parts):
            if pp.startswith(":"):
                params[pp[1:]] = rp
            elif pp != rp:
                return False, {}
        return True, params

    def do_GET(self):
        self.route()
        conn = get_db()
        try:
            ok, p = self.match("GET", "/api/v1/health")
            if ok:
                json_response(self, {"status":"ok","version":"1.0.0","db":"sqlite3","server":"Python stdlib"})
                return

            ok, p = self.match("GET", "/api/v1/stats")
            if ok:
                user = get_auth_user(self)
                if not user: return error_response(self, "Unauthorized", 401)
                stats = {
                    "total_patients": conn.execute("SELECT COUNT(*) FROM patients").fetchone()[0],
                    "active_patients": conn.execute("SELECT COUNT(*) FROM patients WHERE status='active'").fetchone()[0],
                    "total_doctors": conn.execute("SELECT COUNT(*) FROM doctors WHERE status='active'").fetchone()[0],
                    "today_appointments": conn.execute("SELECT COUNT(*) FROM appointments WHERE appointment_date=date('now')").fetchone()[0],
                    "pending_appointments": conn.execute("SELECT COUNT(*) FROM appointments WHERE status='scheduled'").fetchone()[0],
                    "total_revenue": conn.execute("SELECT COALESCE(SUM(amount),0) FROM invoices WHERE status='paid'").fetchone()[0],
                    "pending_revenue": conn.execute("SELECT COALESCE(SUM(amount),0) FROM invoices WHERE status='pending'").fetchone()[0],
                    "overdue_revenue": conn.execute("SELECT COALESCE(SUM(amount),0) FROM invoices WHERE status='overdue'").fetchone()[0],
                    "active_prescriptions": conn.execute("SELECT COUNT(*) FROM prescriptions WHERE status='active'").fetchone()[0],
                }
                json_response(self, stats)
                return

            ok, p = self.match("GET", "/api/v1/patients")
            if ok:
                user = get_auth_user(self)
                if not user: return error_response(self, "Unauthorized", 401)
                rows = conn.execute("SELECT * FROM patients ORDER BY created_at DESC").fetchall()
                log_request(conn,"INFO",f"Fetched {len(rows)} patients","/api/v1/patients",user.get("email",""))
                json_response(self, rows_to_list(rows))
                return

            ok, p = self.match("GET", "/api/v1/patients/:id")
            if ok:
                user = get_auth_user(self)
                if not user: return error_response(self, "Unauthorized", 401)
                row = conn.execute("SELECT * FROM patients WHERE id=?", (p["id"],)).fetchone()
                if not row: return error_response(self, "Patient not found", 404)
                json_response(self, dict(row))
                return

            ok, p = self.match("GET", "/api/v1/doctors")
            if ok:
                user = get_auth_user(self)
                if not user: return error_response(self, "Unauthorized", 401)
                rows = conn.execute("SELECT * FROM doctors ORDER BY name").fetchall()
                json_response(self, rows_to_list(rows))
                return

            ok, p = self.match("GET", "/api/v1/doctors/:id")
            if ok:
                user = get_auth_user(self)
                if not user: return error_response(self, "Unauthorized", 401)
                row = conn.execute("SELECT * FROM doctors WHERE id=?", (p["id"],)).fetchone()
                if not row: return error_response(self, "Doctor not found", 404)
                json_response(self, dict(row))
                return

            ok, p = self.match("GET", "/api/v1/appointments")
            if ok:
                user = get_auth_user(self)
                if not user: return error_response(self, "Unauthorized", 401)
                status_filter = self.query.get("status",["all"])[0]
                if status_filter != "all":
                    rows = conn.execute("SELECT * FROM appointments WHERE status=? ORDER BY appointment_date DESC, appointment_time", (status_filter,)).fetchall()
                else:
                    rows = conn.execute("SELECT * FROM appointments ORDER BY appointment_date DESC, appointment_time").fetchall()
                json_response(self, rows_to_list(rows))
                return

            ok, p = self.match("GET", "/api/v1/prescriptions")
            if ok:
                user = get_auth_user(self)
                if not user: return error_response(self, "Unauthorized", 401)
                rows = conn.execute("SELECT * FROM prescriptions ORDER BY issued_at DESC").fetchall()
                json_response(self, rows_to_list(rows))
                return

            ok, p = self.match("GET", "/api/v1/billing")
            if ok:
                user = get_auth_user(self)
                if not user: return error_response(self, "Unauthorized", 401)
                rows = conn.execute("SELECT * FROM invoices ORDER BY created_at DESC").fetchall()
                json_response(self, rows_to_list(rows))
                return

            ok, p = self.match("GET", "/api/v1/logs")
            if ok:
                user = get_auth_user(self)
                if not user: return error_response(self, "Unauthorized", 401)
                if user.get("role") != "admin": return error_response(self, "Forbidden", 403)
                level_filter = self.query.get("level",["all"])[0]
                if level_filter != "all":
                    rows = conn.execute("SELECT * FROM logs WHERE level=? ORDER BY id DESC LIMIT 60", (level_filter.upper(),)).fetchall()
                else:
                    rows = conn.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 60").fetchall()
                json_response(self, rows_to_list(rows))
                return

            ok, p = self.match("GET", "/api/v1/analytics")
            if ok:
                user = get_auth_user(self)
                if not user: return error_response(self, "Unauthorized", 401)
                dept_rows = conn.execute("""
                    SELECT department, COUNT(*) as count FROM appointments GROUP BY department ORDER BY count DESC
                """).fetchall()
                monthly = conn.execute("""
                    SELECT strftime('%Y-%m', invoice_date) as month,
                           SUM(CASE WHEN status='paid' THEN amount ELSE 0 END) as revenue,
                           COUNT(*) as invoices
                    FROM invoices GROUP BY month ORDER BY month DESC LIMIT 6
                """).fetchall()
                top_diagnoses = conn.execute("""
                    SELECT medical_history as diagnosis, COUNT(*) as count
                    FROM patients WHERE medical_history != 'None' AND medical_history != ''
                    GROUP BY medical_history ORDER BY count DESC LIMIT 5
                """).fetchall()
                json_response(self, {
                    "departments": rows_to_list(dept_rows),
                    "monthly_revenue": rows_to_list(monthly),
                    "top_diagnoses": rows_to_list(top_diagnoses),
                    "bed_occupancy": 73,
                    "patient_satisfaction": 94,
                    "avg_wait_time": 18,
                    "readmission_rate": 4.2,
                })
                return

            error_response(self, "Not found", 404)
        finally:
            conn.close()

    def do_POST(self):
        self.route()
        conn = get_db()
        try:
            ok, p = self.match("POST", "/api/v1/auth/login")
            if ok:
                body = read_body(self)
                email = body.get("email","").strip()
                password = body.get("password","").strip()
                if not email or not password:
                    return error_response(self, "Email and password required")
                user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
                if not user or user["password_hash"] != hash_password(password):
                    log_request(conn,"WARN",f"Failed login attempt for {email}","/api/v1/auth/login")
                    return error_response(self, "Invalid credentials", 401)
                token = create_token({"sub": user["id"], "email": user["email"], "role": user["role"], "name": user["name"]})
                log_request(conn,"INFO",f"Login successful: {email}","/api/v1/auth/login", email)
                json_response(self, {"token": token, "user": {"id": user["id"], "name": user["name"], "email": user["email"], "role": user["role"]}})
                return

            ok, p = self.match("POST", "/api/v1/auth/logout")
            if ok:
                user = get_auth_user(self)
                if user:
                    log_request(conn,"INFO",f"Logout: {user.get('email','')}","/api/v1/auth/logout",user.get("email",""))
                json_response(self, {"message": "Logged out"})
                return

            ok, p = self.match("POST", "/api/v1/patients")
            if ok:
                user = get_auth_user(self)
                if not user: return error_response(self, "Unauthorized", 401)
                body = read_body(self)
                pid = "P" + str(int(time.time() * 1000))[-6:]
                conn.execute("""INSERT INTO patients (id,name,dob,gender,blood_type,phone,address,medical_history,status)
                    VALUES (?,?,?,?,?,?,?,?,?)""",
                    (pid, body.get("name",""), body.get("dob",""), body.get("gender",""),
                     body.get("blood_type",""), body.get("phone",""), body.get("address",""),
                     body.get("medical_history",""), "active"))
                conn.commit()
                log_request(conn,"INFO",f"New patient registered: {body.get('name','')}","/api/v1/patients",user.get("email",""))
                row = conn.execute("SELECT * FROM patients WHERE id=?", (pid,)).fetchone()
                json_response(self, dict(row), 201)
                return

            ok, p = self.match("POST", "/api/v1/doctors")
            if ok:
                user = get_auth_user(self)
                if not user or user.get("role") != "admin": return error_response(self, "Forbidden", 403)
                body = read_body(self)
                did = "D" + str(int(time.time() * 1000))[-3:]
                conn.execute("""INSERT INTO doctors (id,name,specialty,license_no,email,phone,availability)
                    VALUES (?,?,?,?,?,?,?)""",
                    (did, body.get("name",""), body.get("specialty",""), body.get("license_no",""),
                     body.get("email",""), body.get("phone",""), body.get("availability","Full Time")))
                conn.commit()
                log_request(conn,"INFO",f"Doctor added: {body.get('name','')}","/api/v1/doctors",user.get("email",""))
                row = conn.execute("SELECT * FROM doctors WHERE id=?", (did,)).fetchone()
                json_response(self, dict(row), 201)
                return

            ok, p = self.match("POST", "/api/v1/appointments")
            if ok:
                user = get_auth_user(self)
                if not user: return error_response(self, "Unauthorized", 401)
                body = read_body(self)
                aid = "A" + str(int(time.time() * 1000))[-6:]
                conn.execute("""INSERT INTO appointments (id,patient_id,patient_name,doctor_id,doctor_name,department,room,appointment_date,appointment_time,notes)
                    VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (aid, body.get("patient_id",""), body.get("patient_name",""),
                     body.get("doctor_id",""), body.get("doctor_name",""), body.get("department",""),
                     body.get("room",""), body.get("appointment_date",""), body.get("appointment_time",""),
                     body.get("notes","")))
                conn.commit()
                log_request(conn,"INFO",f"Appointment booked: {body.get('patient_name','')} with {body.get('doctor_name','')}","/api/v1/appointments",user.get("email",""))
                row = conn.execute("SELECT * FROM appointments WHERE id=?", (aid,)).fetchone()
                json_response(self, dict(row), 201)
                return

            ok, p = self.match("POST", "/api/v1/prescriptions")
            if ok:
                user = get_auth_user(self)
                if not user: return error_response(self, "Unauthorized", 401)
                body = read_body(self)
                rid = "RX" + str(int(time.time() * 1000))[-5:]
                conn.execute("""INSERT INTO prescriptions (id,patient_id,patient_name,doctor_id,doctor_name,medication,dosage,duration,refills,instructions)
                    VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (rid, body.get("patient_id",""), body.get("patient_name",""),
                     body.get("doctor_id",""), body.get("doctor_name",""), body.get("medication",""),
                     body.get("dosage",""), body.get("duration",""), body.get("refills",0), body.get("instructions","")))
                conn.commit()
                log_request(conn,"INFO",f"Prescription issued: {body.get('medication','')} for {body.get('patient_name','')}","/api/v1/prescriptions",user.get("email",""))
                row = conn.execute("SELECT * FROM prescriptions WHERE id=?", (rid,)).fetchone()
                json_response(self, dict(row), 201)
                return

            ok, p = self.match("POST", "/api/v1/billing")
            if ok:
                user = get_auth_user(self)
                if not user: return error_response(self, "Unauthorized", 401)
                body = read_body(self)
                iid = "INV-" + str(int(time.time() * 1000))[-4:]
                conn.execute("""INSERT INTO invoices (id,patient_id,patient_name,service,amount,status)
                    VALUES (?,?,?,?,?,?)""",
                    (iid, body.get("patient_id",""), body.get("patient_name",""),
                     body.get("service",""), float(body.get("amount",0)), body.get("status","pending")))
                conn.commit()
                log_request(conn,"INFO",f"Invoice created: {iid} for ${body.get('amount',0)}","/api/v1/billing",user.get("email",""))
                row = conn.execute("SELECT * FROM invoices WHERE id=?", (iid,)).fetchone()
                json_response(self, dict(row), 201)
                return

            error_response(self, "Not found", 404)
        finally:
            conn.close()

    def do_PUT(self):
        self.route()
        conn = get_db()
        try:
            ok, p = self.match("PUT", "/api/v1/patients/:id")
            if ok:
                user = get_auth_user(self)
                if not user: return error_response(self, "Unauthorized", 401)
                body = read_body(self)
                fields = {k: v for k, v in body.items() if k in ["name","dob","gender","blood_type","phone","address","medical_history","status"]}
                if not fields: return error_response(self, "No valid fields to update")
                set_clause = ", ".join(f"{k}=?" for k in fields)
                conn.execute(f"UPDATE patients SET {set_clause} WHERE id=?", list(fields.values()) + [p["id"]])
                conn.commit()
                log_request(conn,"INFO",f"Patient updated: {p['id']}",f"/api/v1/patients/{p['id']}",user.get("email",""))
                row = conn.execute("SELECT * FROM patients WHERE id=?", (p["id"],)).fetchone()
                json_response(self, dict(row))
                return

            ok, p = self.match("PUT", "/api/v1/appointments/:id")
            if ok:
                user = get_auth_user(self)
                if not user: return error_response(self, "Unauthorized", 401)
                body = read_body(self)
                fields = {k: v for k, v in body.items() if k in ["status","notes","room","appointment_date","appointment_time","department"]}
                if not fields: return error_response(self, "No valid fields to update")
                set_clause = ", ".join(f"{k}=?" for k in fields)
                conn.execute(f"UPDATE appointments SET {set_clause} WHERE id=?", list(fields.values()) + [p["id"]])
                conn.commit()
                log_request(conn,"INFO",f"Appointment {p['id']} updated to {body.get('status','')}",f"/api/v1/appointments/{p['id']}",user.get("email",""))
                row = conn.execute("SELECT * FROM appointments WHERE id=?", (p["id"],)).fetchone()
                json_response(self, dict(row))
                return

            ok, p = self.match("PUT", "/api/v1/billing/:id")
            if ok:
                user = get_auth_user(self)
                if not user: return error_response(self, "Unauthorized", 401)
                body = read_body(self)
                fields = {k: v for k, v in body.items() if k in ["status","amount","service"]}
                if not fields: return error_response(self, "No valid fields to update")
                set_clause = ", ".join(f"{k}=?" for k in fields)
                conn.execute(f"UPDATE invoices SET {set_clause} WHERE id=?", list(fields.values()) + [p["id"]])
                conn.commit()
                log_request(conn,"INFO",f"Invoice {p['id']} updated",f"/api/v1/billing/{p['id']}",user.get("email",""))
                row = conn.execute("SELECT * FROM invoices WHERE id=?", (p["id"],)).fetchone()
                json_response(self, dict(row))
                return

            error_response(self, "Not found", 404)
        finally:
            conn.close()

    def do_DELETE(self):
        self.route()
        conn = get_db()
        try:
            ok, p = self.match("DELETE", "/api/v1/appointments/:id")
            if ok:
                user = get_auth_user(self)
                if not user: return error_response(self, "Unauthorized", 401)
                row = conn.execute("SELECT * FROM appointments WHERE id=?", (p["id"],)).fetchone()
                if not row: return error_response(self, "Not found", 404)
                conn.execute("DELETE FROM appointments WHERE id=?", (p["id"],))
                conn.commit()
                log_request(conn,"WARN",f"Appointment {p['id']} deleted",f"/api/v1/appointments/{p['id']}",user.get("email",""))
                json_response(self, {"message": "Deleted", "id": p["id"]})
                return

            ok, p = self.match("DELETE", "/api/v1/patients/:id")
            if ok:
                user = get_auth_user(self)
                if not user or user.get("role") != "admin": return error_response(self, "Forbidden", 403)
                conn.execute("DELETE FROM patients WHERE id=?", (p["id"],))
                conn.commit()
                log_request(conn,"WARN",f"Patient {p['id']} deleted",f"/api/v1/patients/{p['id']}",user.get("email",""))
                json_response(self, {"message": "Deleted", "id": p["id"]})
                return

            error_response(self, "Not found", 404)
        finally:
            conn.close()


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    server = HTTPServer(("0.0.0.0", PORT), HMSHandler)
    print(f"""
╔══════════════════════════════════════════════╗
║       MediCore HMS — Python Backend          ║
╠══════════════════════════════════════════════╣
║  Server  : http://localhost:{PORT}              ║
║  Database: SQLite (medicore.db)              ║
║  Auth    : JWT (HMAC-SHA256)                 ║
╠══════════════════════════════════════════════╣
║  Endpoints:                                  ║
║   POST /api/v1/auth/login                    ║
║   GET  /api/v1/stats                         ║
║   GET  /api/v1/patients                      ║
║   POST /api/v1/patients                      ║
║   GET  /api/v1/doctors                       ║
║   GET  /api/v1/appointments                  ║
║   POST /api/v1/appointments                  ║
║   GET  /api/v1/prescriptions                 ║
║   GET  /api/v1/billing                       ║
║   GET  /api/v1/analytics                     ║
║   GET  /api/v1/logs  (admin only)            ║
╠══════════════════════════════════════════════╣
║  Demo users:                                 ║
║   admin@medicore.com  / admin123             ║
║   doctor@medicore.com / doctor123            ║
║   patient@medicore.com/ patient123           ║
╚══════════════════════════════════════════════╝
Press Ctrl+C to stop.
""")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Server] Stopped.")
