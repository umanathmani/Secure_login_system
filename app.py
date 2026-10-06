import os
import sqlite3
import time
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt

from security.risk_engine import calculate_risk


# ==================================================
# APP CONFIGURATION
# ==================================================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "secure-login-demo-change-this-key"
)

bcrypt = Bcrypt(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "database.db")


# ==================================================
# DATABASE
# ==================================================

def get_db():

    conn = sqlite3.connect(
        DATABASE,
        timeout=10
    )

    conn.row_factory = sqlite3.Row

    return conn


def init_db():

    conn = get_db()
    cur = conn.cursor()

    # --------------------------------------------------
    # USERS TABLE
    # --------------------------------------------------

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            username TEXT UNIQUE NOT NULL,

            password TEXT NOT NULL

        )
    """)

    # --------------------------------------------------
    # LOGIN HISTORY TABLE
    # --------------------------------------------------

    cur.execute("""
        CREATE TABLE IF NOT EXISTS login_history (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            username TEXT,

            ip_address TEXT,

            device TEXT,

            status TEXT,

            timestamp TEXT

        )
    """)

    # --------------------------------------------------
    # CHECK EXISTING COLUMNS
    # --------------------------------------------------

    cur.execute(
        "PRAGMA table_info(login_history)"
    )

    columns = {
        row["name"]
        for row in cur.fetchall()
    }

    required_columns = {
        "username": "TEXT",
        "ip_address": "TEXT",
        "device": "TEXT",
        "status": "TEXT",
        "timestamp": "TEXT"
    }

    for column, column_type in required_columns.items():

        if column not in columns:

            cur.execute(
                f"""
                ALTER TABLE login_history
                ADD COLUMN {column} {column_type}
                """
            )

    conn.commit()
    conn.close()


# ==================================================
# RECORD LOGIN HISTORY
# ==================================================

def record_attempt(username, status):

    ip_address = request.headers.get(
        "X-Forwarded-For",
        request.remote_addr or "Unknown"
    ).split(",")[0].strip()

    device = request.headers.get(
        "User-Agent",
        "Unknown Device"
    )

    timestamp = time.strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    conn = get_db()

    try:

        # Find user
        user = conn.execute(
            """
            SELECT id
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        # If username does not exist
        if user is None:

            conn.close()

            return

        user_id = user["id"]

        # Check database structure
        cur = conn.execute(
            "PRAGMA table_info(login_history)"
        )

        columns = {
            row["name"]
            for row in cur.fetchall()
        }

        # --------------------------------------------------
        # OLD DATABASE WITH USER_ID
        # --------------------------------------------------

        if "user_id" in columns:

            conn.execute(
                """
                INSERT INTO login_history
                (
                    user_id,
                    username,
                    ip_address,
                    device,
                    status,
                    timestamp
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    username,
                    ip_address,
                    device,
                    status,
                    timestamp
                )
            )

        # --------------------------------------------------
        # NORMAL DATABASE
        # --------------------------------------------------

        else:

            conn.execute(
                """
                INSERT INTO login_history
                (
                    username,
                    ip_address,
                    device,
                    status,
                    timestamp
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    username,
                    ip_address,
                    device,
                    status,
                    timestamp
                )
            )

        conn.commit()

    except sqlite3.Error as error:

        app.logger.error(
            f"Login history error: {error}"
        )

    finally:

        conn.close()


# ==================================================
# LOGIN REQUIRED
# ==================================================

def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:

            return redirect(
                url_for("login")
            )

        return function(
            *args,
            **kwargs
        )

    return wrapper


# ==================================================
# HOME
# ==================================================

@app.route("/")
def home():

    if "user_id" in session:

        return redirect(
            url_for("dashboard")
        )

    return redirect(
        url_for("login")
    )


# ==================================================
# REGISTER
# ==================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if request.method == "GET":

        return render_template(
            "register.html"
        )

    username = request.form.get(
        "username",
        ""
    ).strip()

    password = request.form.get(
        "password",
        ""
    )

    # Empty validation
    if not username or not password:

        return render_template(
            "register.html",
            error="Please enter username and password."
        )

    # Password length
    if len(password) < 8:

        return render_template(
            "register.html",
            error="Password must be at least 8 characters."
        )

    conn = get_db()

    try:

        password_hash = bcrypt.generate_password_hash(
            password
        ).decode("utf-8")

        conn.execute(
            """
            INSERT INTO users
            (
                username,
                password
            )
            VALUES (?, ?)
            """,
            (
                username,
                password_hash
            )
        )

        conn.commit()

    except sqlite3.IntegrityError:

        return render_template(
            "register.html",
            error="Username already exists."
        )

    except sqlite3.Error as error:

        app.logger.error(
            f"Registration error: {error}"
        )

        return render_template(
            "register.html",
            error="Registration failed."
        )

    finally:

        conn.close()

    flash(
        "Registration successful. Please log in."
    )

    return redirect(
        url_for("login")
    )


# ==================================================
# LOGIN
# ==================================================

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
        "username",
        ""
    ).strip()

    password = request.form.get(
        "password",
        ""
    )

    # Empty validation
    if not username or not password:

        return render_template(
            "login.html",
            error="Please enter username and password."
        )

    # --------------------------------------------------
    # FIND USER
    # --------------------------------------------------

    conn = get_db()

    user = conn.execute(
        """
        SELECT
            id,
            username,
            password
        FROM users
        WHERE username = ?
        """,
        (username,)
    ).fetchone()

    conn.close()

    # --------------------------------------------------
    # USER NOT FOUND
    # --------------------------------------------------

    if user is None:

        record_attempt(
            username,
            "Failed"
        )

        return render_template(
            "login.html",
            error="Invalid username or password."
        )

    # --------------------------------------------------
    # PASSWORD CHECK
    # --------------------------------------------------

    try:

        password_correct = (
            bcrypt.check_password_hash(
                user["password"],
                password
            )
        )

    except Exception:

        password_correct = False

    # --------------------------------------------------
    # WRONG PASSWORD
    # --------------------------------------------------

    if not password_correct:

        record_attempt(
            username,
            "Failed"
        )

        return render_template(
            "login.html",
            error="Invalid username or password."
        )

    # ==================================================
    # SUCCESSFUL LOGIN
    # ==================================================

    ip_address = request.headers.get(
        "X-Forwarded-For",
        request.remote_addr or "Unknown"
    ).split(",")[0].strip()

    device = request.headers.get(
        "User-Agent",
        "Unknown Device"
    )

    device_display = device[:100]

    login_time = time.strftime(
        "%d-%m-%Y %I:%M %p"
    )

    # ==================================================
    # PREVIOUS LOGIN CHECK
    # ==================================================

    conn = get_db()

    previous_login = conn.execute(
        """
        SELECT
            ip_address,
            device,
            timestamp,
            status

        FROM login_history

        WHERE username = ?

        AND status = 'Success'

        ORDER BY id DESC

        LIMIT 1
        """,
        (username,)
    ).fetchone()

    conn.close()

    # Default risk signals
    new_ip = False
    new_device = False
    unusual_time = False
    unusual_location = False
    failed_attempts = 0

    # --------------------------------------------------
    # COMPARE PREVIOUS LOGIN
    # --------------------------------------------------

    if previous_login:

        previous_ip = previous_login["ip_address"]

        previous_device = previous_login["device"]

        if (
            previous_ip
            and previous_ip != ip_address
        ):

            new_ip = True

        if (
            previous_device
            and previous_device != device
        ):

            new_device = True

    # ==================================================
    # RISK ENGINE
    # ==================================================

    try:

        risk_result = calculate_risk(

            new_device=new_device,

            new_ip=new_ip,

            unusual_time=unusual_time,

            failed_attempts=failed_attempts,

            unusual_location=unusual_location

        )

        risk_score = risk_result.get(
            "score",
            0
        )

        risk_level = risk_result.get(
            "level",
            "LOW"
        )

        risk_reasons = risk_result.get(
            "reasons",
            []
        )

    except Exception:

        app.logger.exception(
            "Risk engine error"
        )

        risk_score = 0
        risk_level = "LOW"
        risk_reasons = []

    # ==================================================
    # CREATE RISK OBJECT
    # ==================================================

    risk = {
        "score": risk_score,
        "level": risk_level,
        "reasons": risk_reasons
    }

    # ==================================================
    # SAVE SESSION
    # ==================================================

    session.clear()

    session["user_id"] = user["id"]

    session["username"] = user["username"]

    session["risk_score"] = risk_score

    session["risk_level"] = risk_level

    session["risk_reasons"] = risk_reasons

    # ==================================================
    # RECORD SUCCESSFUL LOGIN
    # ==================================================

    record_attempt(
        username,
        "Success"
    )

    # ==================================================
    # DIRECT DASHBOARD
    # ==================================================

    return render_template(

        "dashboard.html",

        username=user["username"],

        ip_address=ip_address,

        ip=ip_address,

        device=device_display,

        login_time=login_time,

        risk=risk,

        risk_score=risk_score,

        risk_level=risk_level,

        risk_reasons=risk_reasons,

        history=get_login_history(username)

    )


# ==================================================
# GET LOGIN HISTORY
# ==================================================

def get_login_history(username):

    conn = get_db()

    try:

        history = conn.execute(
            """
            SELECT
                username,
                ip_address,
                device,
                status,
                timestamp

            FROM login_history

            WHERE username = ?

            ORDER BY id DESC

            LIMIT 20
            """,
            (username,)
        ).fetchall()

        return history

    except sqlite3.Error as error:

        app.logger.error(
            f"History error: {error}"
        )

        return []

    finally:

        conn.close()


# ==================================================
# DASHBOARD
# ==================================================

@app.route("/dashboard")
@login_required
def dashboard():

    username = session.get(
        "username"
    )

    history = get_login_history(
        username
    )

    # --------------------------------------------------
    # GET LATEST LOGIN
    # --------------------------------------------------

    latest_login = None

    if history:

        latest_login = history[0]

    if latest_login:

        ip_address = latest_login["ip_address"]

        device = latest_login["device"]

        raw_timestamp = latest_login["timestamp"]

        try:

            parsed_time = time.strptime(
                raw_timestamp,
                "%Y-%m-%d %H:%M:%S"
            )

            login_time = time.strftime(
                "%d-%m-%Y %I:%M %p",
                parsed_time
            )

        except Exception:

            login_time = raw_timestamp

    else:

        ip_address = "Unknown"

        device = "Unknown Device"

        login_time = "Unknown"

    # --------------------------------------------------
    # RISK FROM SESSION
    # --------------------------------------------------

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

    risk = {
        "score": risk_score,
        "level": risk_level,
        "reasons": risk_reasons
    }

    # --------------------------------------------------
    # RENDER DASHBOARD
    # --------------------------------------------------

    return render_template(

        "dashboard.html",

        username=username,

        ip_address=ip_address,

        ip=ip_address,

        device=device,

        login_time=login_time,

        history=history,

        risk=risk,

        risk_score=risk_score,

        risk_level=risk_level,

        risk_reasons=risk_reasons

    )


# ==================================================
# SUCCESS PAGE
# ==================================================

@app.route("/success")
@login_required
def success():

    return render_template(

        "success.html",

        username=session.get(
            "username"
        )

    )


# ==================================================
# LOGOUT
# ==================================================

@app.route(
    "/logout",
    methods=["GET", "POST"]
)
def logout():

    session.clear()

    flash(
        "You have been logged out."
    )

    return redirect(
        url_for("login")
    )


# ==================================================
# START APPLICATION
# ==================================================

if __name__ == "__main__":

    init_db()

    app.run(
        debug=True
    )