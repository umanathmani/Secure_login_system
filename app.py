from flask import Flask, render_template, request, redirect, url_for, session
from flask_bcrypt import Bcrypt
from twilio.rest import Client
from dotenv import load_dotenv

import sqlite3
import os
from datetime import datetime

from security.risk_engine import calculate_risk


# =========================================================
# LOAD ENVIRONMENT VARIABLES
# =========================================================

load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv(
    "SECRET_KEY",
    "secure-login-system-secret-key"
)

bcrypt = Bcrypt(app)


# =========================================================
# HOME PAGE
# =========================================================

@app.route("/")
def home():
    return redirect(url_for("login"))


# =========================================================
# TWILIO CONFIGURATION
# =========================================================

TWILIO_ACCOUNT_SID = os.getenv(
    "TWILIO_ACCOUNT_SID"
)

TWILIO_AUTH_TOKEN = os.getenv(
    "TWILIO_AUTH_TOKEN"
)

TWILIO_VERIFY_SERVICE_SID = os.getenv(
    "TWILIO_VERIFY_SERVICE_SID"
)


if TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN:

    twilio_client = Client(
        TWILIO_ACCOUNT_SID,
        TWILIO_AUTH_TOKEN
    )

else:

    twilio_client = None


# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_db():

    conn = sqlite3.connect(
        "database.db"
    )

    conn.row_factory = sqlite3.Row

    return conn


# =========================================================
# INITIALIZE DATABASE
# =========================================================

def init_db():

    conn = get_db()

    cursor = conn.cursor()

    # USERS TABLE
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            username TEXT UNIQUE NOT NULL,

            email TEXT UNIQUE,

            password TEXT NOT NULL,

            phone TEXT,

            phone_verified INTEGER DEFAULT 0,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # LOGIN HISTORY TABLE
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_history (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            username TEXT,

            status TEXT,

            ip_address TEXT,

            device TEXT,

            login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            risk_score INTEGER DEFAULT 0,

            risk_level TEXT DEFAULT 'LOW'
        )
    """)

    # CHECK USERS TABLE COLUMNS
    columns = cursor.execute(
        "PRAGMA table_info(users)"
    ).fetchall()

    column_names = [
        column["name"]
        for column in columns
    ]

    # ADD ACCOUNT LOCK COLUMN
    if "is_locked" not in column_names:

        cursor.execute("""
            ALTER TABLE users
            ADD COLUMN is_locked INTEGER DEFAULT 0
        """)

    conn.commit()

    conn.close()


# =========================================================
# RECORD LOGIN ATTEMPT
# =========================================================

def record_attempt(
    username,
    status,
    ip_address,
    device,
    risk_score=0,
    risk_level="LOW"
):

    conn = get_db()

    cursor = conn.cursor()

    login_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    cursor.execute("""
        INSERT INTO login_history
        (
            username,
            status,
            ip_address,
            device,
            login_time,
            risk_score,
            risk_level
        )

        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        username,
        status,
        ip_address,
        device,
        login_time,
        risk_score,
        risk_level
    ))

    conn.commit()

    conn.close()


# =========================================================
# GET FAILED ATTEMPTS AFTER LAST SUCCESS OR RECOVERY
# =========================================================

def get_recent_failed_attempts(username):

    conn = get_db()

    cursor = conn.cursor()

    # Latest successful login OR account recovery
    last_reset = cursor.execute("""
        SELECT id
        FROM login_history
        WHERE username = ?
        AND status IN ('SUCCESS', 'RECOVERY')
        ORDER BY id DESC
        LIMIT 1
    """, (username,)).fetchone()

    if last_reset:

        failed_count = cursor.execute("""
            SELECT COUNT(*)
            FROM login_history
            WHERE username = ?
            AND status = 'FAILED'
            AND id > ?
        """, (
            username,
            last_reset["id"]
        )).fetchone()[0]

    else:

        failed_count = cursor.execute("""
            SELECT COUNT(*)
            FROM login_history
            WHERE username = ?
            AND status = 'FAILED'
        """, (username,)).fetchone()[0]

    conn.close()

    return failed_count


# =========================================================
# CHECK NEW DEVICE
# =========================================================

def is_new_device(
    username,
    current_device
):

    conn = get_db()

    cursor = conn.cursor()

    previous_login = cursor.execute("""
        SELECT device
        FROM login_history
        WHERE username = ?
        AND status = 'SUCCESS'
        ORDER BY id DESC
        LIMIT 1
    """, (username,)).fetchone()

    conn.close()

    if not previous_login:

        return True

    return (
        previous_login["device"]
        != current_device
    )


# =========================================================
# CHECK NEW IP
# =========================================================

def is_new_ip(
    username,
    current_ip
):

    conn = get_db()

    cursor = conn.cursor()

    previous_login = cursor.execute("""
        SELECT ip_address
        FROM login_history
        WHERE username = ?
        AND status = 'SUCCESS'
        ORDER BY id DESC
        LIMIT 1
    """, (username,)).fetchone()

    conn.close()

    if not previous_login:

        return True

    return (
        previous_login["ip_address"]
        != current_ip
    )


# =========================================================
# CHECK UNUSUAL LOGIN TIME
# =========================================================

def is_unusual_login_time(username):

    conn = get_db()

    cursor = conn.cursor()

    previous_login = cursor.execute("""
        SELECT login_time
        FROM login_history
        WHERE username = ?
        AND status = 'SUCCESS'
        ORDER BY id DESC
        LIMIT 1
    """, (username,)).fetchone()

    conn.close()

    if not previous_login:

        return False

    try:

        previous_time = datetime.strptime(
            previous_login["login_time"],
            "%Y-%m-%d %H:%M:%S"
        )

        current_time = datetime.now()

        previous_hour = previous_time.hour

        current_hour = current_time.hour

        hour_difference = abs(
            current_hour - previous_hour
        )

        hour_difference = min(
            hour_difference,
            24 - hour_difference
        )

        return hour_difference > 2

    except Exception:

        return False


# =========================================================
# SEND OTP
# =========================================================

def send_otp(phone):

    if not twilio_client:

        return False

    try:

        verification = (
            twilio_client
            .verify
            .v2
            .services(
                TWILIO_VERIFY_SERVICE_SID
            )
            .verifications
            .create(
                to=phone,
                channel="sms"
            )
        )

        return (
            verification.status
            == "pending"
        )

    except Exception as e:

        print(
            "OTP SEND ERROR:",
            e
        )

        return False


# =========================================================
# VERIFY OTP
# =========================================================

def verify_otp(
    phone,
    otp
):

    if not twilio_client:

        return False

    try:

        verification_check = (
            twilio_client
            .verify
            .v2
            .services(
                TWILIO_VERIFY_SERVICE_SID
            )
            .verification_checks
            .create(
                to=phone,
                code=otp
            )
        )

        return (
            verification_check.status
            == "approved"
        )

    except Exception as e:

        print(
            "OTP VERIFY ERROR:",
            e
        )

        return False


# =========================================================
# REGISTER
# =========================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if request.method == "POST":

        username = request.form.get(
            "username"
        )

        email = request.form.get(
            "email"
        )

        phone = request.form.get(
            "phone"
        )

        password = request.form.get(
            "password"
        )

        if not username or not password:

            return render_template(
                "register.html",
                error=(
                    "Username and password "
                    "are required."
                )
            )

        conn = get_db()

        cursor = conn.cursor()

        existing_user = cursor.execute("""
            SELECT *
            FROM users
            WHERE username = ?
        """, (username,)).fetchone()

        if existing_user:

            conn.close()

            return render_template(
                "register.html",
                error=(
                    "Username already exists."
                )
            )

        hashed_password = (
            bcrypt
            .generate_password_hash(
                password
            )
            .decode("utf-8")
        )

        cursor.execute("""
            INSERT INTO users
            (
                username,
                email,
                password,
                phone,
                phone_verified,
                is_locked
            )

            VALUES (?, ?, ?, ?, 0, 0)
        """, (
            username,
            email,
            hashed_password,
            phone
        ))

        conn.commit()

        conn.close()

        session[
            "registration_username"
        ] = username

        session[
            "registration_phone"
        ] = phone

        if phone:

            if send_otp(phone):

                return redirect(
                    url_for(
                        "verify_registration"
                    )
                )

            return render_template(
                "register.html",
                error=(
                    "Unable to send OTP. "
                    "Please check your "
                    "Twilio configuration."
                )
            )

        return redirect(
            url_for("login")
        )

    return render_template(
        "register.html"
    )


# =========================================================
# VERIFY REGISTRATION OTP
# =========================================================

@app.route(
    "/verify-registration",
    methods=["GET", "POST"]
)
def verify_registration():

    username = session.get(
        "registration_username"
    )

    phone = session.get(
        "registration_phone"
    )

    if not username or not phone:

        return redirect(
            url_for("register")
        )

    if request.method == "POST":

        otp = request.form.get(
            "otp"
        )

        if verify_otp(
            phone,
            otp
        ):

            conn = get_db()

            cursor = conn.cursor()

            cursor.execute("""
                UPDATE users
                SET phone_verified = 1
                WHERE username = ?
            """, (username,))

            conn.commit()

            conn.close()

            session.pop(
                "registration_username",
                None
            )

            session.pop(
                "registration_phone",
                None
            )

            return redirect(
                url_for("login")
            )

        return render_template(
            "verify_registration.html",
            error="Invalid OTP."
        )

    return render_template(
        "verify_registration.html"
    )


# =========================================================
# ACCOUNT RECOVERY
# =========================================================

@app.route(
    "/recover",
    methods=["GET", "POST"]
)
def recover():

    if request.method == "POST":

        username = request.form.get(
            "username"
        )

        conn = get_db()

        cursor = conn.cursor()

        user = cursor.execute("""
            SELECT *
            FROM users
            WHERE username = ?
        """, (username,)).fetchone()

        conn.close()

        if not user:

            return render_template(
                "recover.html",
                error="Username not found."
            )

        if not user["phone"]:

            return render_template(
                "recover.html",
                error=(
                    "No registered phone "
                    "number found."
                )
            )

        if user["phone_verified"] != 1:

            return render_template(
                "recover.html",
                error=(
                    "Registered phone number "
                    "is not verified."
                )
            )

        if send_otp(
            user["phone"]
        ):

            session[
                "recovery_username"
            ] = username

            return redirect(
                url_for(
                    "recovery_otp"
                )
            )

        return render_template(
            "recover.html",
            error=(
                "Unable to send recovery OTP. "
                "Please try again."
            )
        )

    return render_template(
        "recover.html"
    )


# =========================================================
# VERIFY RECOVERY OTP AND UNLOCK ACCOUNT
# =========================================================

@app.route(
    "/recovery-otp",
    methods=["GET", "POST"]
)
def recovery_otp():

    username = session.get(
        "recovery_username"
    )

    if not username:

        return redirect(
            url_for("recover")
        )

    conn = get_db()

    cursor = conn.cursor()

    user = cursor.execute("""
        SELECT *
        FROM users
        WHERE username = ?
    """, (username,)).fetchone()

    conn.close()

    if not user:

        session.pop(
            "recovery_username",
            None
        )

        return redirect(
            url_for("recover")
        )

    if request.method == "POST":

        otp = request.form.get(
            "otp"
        )

        # VERIFY RECOVERY OTP
        if verify_otp(
            user["phone"],
            otp
        ):

            conn = get_db()

            cursor = conn.cursor()

            # UNLOCK ACCOUNT
            cursor.execute("""
                UPDATE users
                SET is_locked = 0
                WHERE username = ?
            """, (username,))

            # CHECK WHETHER UPDATE ACTUALLY HAPPENED
            updated_user = cursor.execute("""
                SELECT is_locked
                FROM users
                WHERE username = ?
            """, (username,)).fetchone()

            if not updated_user:

                conn.close()

                return render_template(
                    "verify_otp.html",
                    error=(
                        "Unable to recover "
                        "the account."
                    )
                )

            if updated_user["is_locked"] != 0:

                conn.close()

                return render_template(
                    "verify_otp.html",
                    error=(
                        "Account unlock failed. "
                        "Please try again."
                    )
                )

            # RECORD RECOVERY RESET
            recovery_time = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            cursor.execute("""
                INSERT INTO login_history
                (
                    username,
                    status,
                    ip_address,
                    device,
                    login_time,
                    risk_score,
                    risk_level
                )

                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                username,
                "RECOVERY",
                "Recovery",
                "Recovery OTP",
                recovery_time,
                0,
                "LOW"
            ))

            conn.commit()

            conn.close()

            # CLEAR RECOVERY SESSION
            session.pop(
                "recovery_username",
                None
            )

            # CLEAR OLD LOGIN SESSION DATA
            session.pop(
                "otp_username",
                None
            )

            session.pop(
                "otp_ip",
                None
            )

            session.pop(
                "otp_device",
                None
            )

            session.pop(
                "risk_score",
                None
            )

            session.pop(
                "risk_level",
                None
            )

            session.pop(
                "risk_reasons",
                None
            )

            print(
                "ACCOUNT RECOVERED:",
                username
            )

            return redirect(
                url_for("login")
            )

        return render_template(
            "verify_otp.html",
            error=(
                "Invalid recovery OTP. "
                "Please try again."
            )
        )

    return render_template(
        "verify_otp.html"
    )


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "GET":

        return render_template(
            "login.html"
        )

    username = request.form.get(
        "username"
    )

    password = request.form.get(
        "password"
    )

    ip_address = (
        request.remote_addr
        or "Unknown"
    )

    device = request.headers.get(
        "User-Agent",
        "Unknown"
    )

    conn = get_db()

    cursor = conn.cursor()

    user = cursor.execute("""
        SELECT *
        FROM users
        WHERE username = ?
    """, (username,)).fetchone()

    conn.close()

    if not user:

        record_attempt(
            username,
            "FAILED",
            ip_address,
            device
        )

        return render_template(
            "login.html",
            error=(
                "Invalid username "
                "or password."
            )
        )

    # =====================================================
    # CHECK LOCKED ACCOUNT
    # =====================================================

    if user["is_locked"] == 1:

        return render_template(
            "login.html",
            error=(
                "Your account is locked. "
                "Please use account recovery."
            )
        )

    # =====================================================
    # CHECK PASSWORD
    # =====================================================

    password_correct = (
        bcrypt.check_password_hash(
            user["password"],
            password
        )
    )

    # =====================================================
    # WRONG PASSWORD
    # =====================================================

    if not password_correct:

        record_attempt(
            username,
            "FAILED",
            ip_address,
            device
        )

        failed_attempts = (
            get_recent_failed_attempts(
                username
            )
        )

        print(
            "FAILED ATTEMPTS:",
            failed_attempts
        )

        # LOCK AFTER 5 FAILED ATTEMPTS
        if failed_attempts >= 5:

            conn = get_db()

            cursor = conn.cursor()

            cursor.execute("""
                UPDATE users
                SET is_locked = 1
                WHERE username = ?
            """, (username,))

            conn.commit()

            conn.close()

            return render_template(
                "login.html",
                error=(
                    "Account locked after "
                    "5 failed attempts. "
                    "Please use account recovery."
                )
            )

        return render_template(
            "login.html",
            error=(
                f"Invalid password. "
                f"Failed attempts: "
                f"{failed_attempts}/5"
            )
        )

    # =====================================================
    # RISK ANALYSIS
    # =====================================================

    new_device = is_new_device(
        username,
        device
    )

    new_ip = is_new_ip(
        username,
        ip_address
    )

    unusual_time = (
        is_unusual_login_time(
            username
        )
    )

    failed_attempts = (
        get_recent_failed_attempts(
            username
        )
    )

    risk = calculate_risk(
        new_device=new_device,
        new_ip=new_ip,
        unusual_time=unusual_time,
        failed_attempts=failed_attempts,
        unusual_location=False
    )

    risk_score = risk["score"]

    risk_level = risk["level"]

    risk_reasons = risk["reasons"]

    print(
        "RISK SCORE:",
        risk_score
    )

    print(
        "RISK LEVEL:",
        risk_level
    )

    print(
        "RISK REASONS:",
        risk_reasons
    )

    # =====================================================
    # SAVE SESSION INFORMATION
    # =====================================================

    session["username"] = username

    session["new_device"] = new_device

    session["device_status"] = (
        "NEW DEVICE DETECTED"
        if new_device
        else "RECOGNIZED DEVICE"
    )

    session["risk_score"] = risk_score

    session["risk_level"] = risk_level

    session["risk_reasons"] = risk_reasons

    session["pending_ip"] = ip_address

    session["pending_device"] = device

    # =====================================================
    # LOW RISK LOGIN
    # =====================================================

    if risk_level == "LOW":

        record_attempt(
            username,
            "SUCCESS",
            ip_address,
            device,
            risk_score,
            risk_level
        )

        return redirect(
            url_for("dashboard")
        )

    # =====================================================
    # MEDIUM / HIGH RISK → OTP
    # =====================================================

    phone = user["phone"]

    if not phone:

        return render_template(
            "login.html",
            error=(
                "Additional verification "
                "is required, but no "
                "registered phone number "
                "is available."
            )
        )

    if user["phone_verified"] != 1:

        return render_template(
            "login.html",
            error=(
                "Your registered phone "
                "number is not verified."
            )
        )

    if send_otp(phone):

        session["otp_username"] = username

        session["otp_ip"] = ip_address

        session["otp_device"] = device

        return redirect(
            url_for("verify_otp_page")
        )

    return render_template(
        "login.html",
        error=(
            "Unable to send OTP. "
            "Please try again."
        )
    )


# =========================================================
# VERIFY LOGIN OTP
# =========================================================

@app.route(
    "/verify-otp",
    methods=["GET", "POST"]
)
def verify_otp_page():

    username = session.get(
        "otp_username"
    )

    if not username:

        return redirect(
            url_for("login")
        )

    if request.method == "POST":

        otp = request.form.get(
            "otp"
        )

        conn = get_db()

        cursor = conn.cursor()

        user = cursor.execute("""
            SELECT *
            FROM users
            WHERE username = ?
        """, (username,)).fetchone()

        conn.close()

        if not user:

            return redirect(
                url_for("login")
            )

        phone = user["phone"]

        if verify_otp(
            phone,
            otp
        ):

            ip_address = session.get(
                "otp_ip",
                "Unknown"
            )

            device = session.get(
                "otp_device",
                "Unknown"
            )

            risk_score = session.get(
                "risk_score",
                0
            )

            risk_level = session.get(
                "risk_level",
                "LOW"
            )

            record_attempt(
                username,
                "SUCCESS",
                ip_address,
                device,
                risk_score,
                risk_level
            )

            session.pop(
                "otp_username",
                None
            )

            session.pop(
                "otp_ip",
                None
            )

            session.pop(
                "otp_device",
                None
            )

            return redirect(
                url_for("dashboard")
            )

        return render_template(
            "verify_otp.html",
            error=(
                "Invalid OTP. "
                "Please try again."
            )
        )

    return render_template(
        "verify_otp.html"
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():

    if "username" not in session:

        return redirect(
            url_for("login")
        )

    username = session[
        "username"
    ]

    conn = get_db()

    cursor = conn.cursor()

    # CURRENT LOGIN
    current_login = cursor.execute("""
        SELECT *
        FROM login_history
        WHERE username = ?
        AND status = 'SUCCESS'
        ORDER BY id DESC
        LIMIT 1
    """, (username,)).fetchone()

    # LOGIN HISTORY
    history = cursor.execute("""
        SELECT *
        FROM login_history
        WHERE username = ?
        ORDER BY id DESC
        LIMIT 10
    """, (username,)).fetchall()

    conn.close()

    if current_login:

        current_ip = (
            current_login["ip_address"]
        )

        current_login_time = (
            current_login["login_time"]
        )

        current_device = (
            current_login["device"]
        )

    else:

        current_ip = "Unknown"

        current_login_time = "Unknown"

        current_device = "Unknown"

    risk_score = session.get(
        "risk_score",
        0
    )

    risk_level = session.get(
        "risk_level",
        "LOW"
    )

    risk_reasons = session.get(
        "risk_reasons",
        []
    )

    new_device = session.get(
        "new_device",
        False
    )

    if new_device:

        device_status = (
            "NEW DEVICE DETECTED"
        )

    else:

        device_status = (
            "RECOGNIZED DEVICE"
        )

    return render_template(
        "dashboard.html",

        username=username,

        current_ip=current_ip,

        current_login_time=(
            current_login_time
        ),

        current_device=(
            current_device
        ),

        new_device=new_device,

        device_status=(
            device_status
        ),

        risk_score=risk_score,

        risk_level=risk_level,

        risk_reasons=(
            risk_reasons
        ),

        history=history
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# =========================================================
# START APPLICATION
# =========================================================

if __name__ == "__main__":

    init_db()

    app.run(
        debug=True
    )