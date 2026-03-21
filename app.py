from flask import Flask, render_template, request, url_for, redirect, session, flash
import sqlite3
import bcrypt
import secrets
import string
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = "supersecretkey"


# ---------------- DATABASE CONNECTION ----------------

def get_db_connection():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn


# ---------------- HOME ----------------

@app.route("/")
def home():
    return render_template("index.html")


# ---------------- LOGIN ----------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        conn = get_db_connection()
        cursor = conn.cursor()

        # 🚫 Check failed attempts in last 24 hours
        last_24 = (datetime.now() - timedelta(hours=24)).isoformat()

        cursor.execute(
            "SELECT COUNT(*) FROM logs WHERE username=? AND status='FAILED' AND time >= ?",
            (username, last_24)
        )

        attempts = cursor.fetchone()[0]

        if attempts >= 3:
            flash("⚠️ Account locked due to suspicious activity (3 failed attempts)")
            conn.close()
            return redirect(url_for("login"))

        # 🔍 Get user
        cursor.execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        )

        user = cursor.fetchone()

        if user:
            stored_password = user["password"]

            if isinstance(stored_password, str):
                stored_password = stored_password.encode()

            if bcrypt.checkpw(password.encode(), stored_password):

                # ✅ SUCCESS LOG
                cursor.execute(
                    "INSERT INTO logs (username, status, time) VALUES (?,?,?)",
                    (username, "SUCCESS", datetime.now().isoformat())
                )

                conn.commit()
                conn.close()

                session["user"] = username
                return redirect(url_for("dashboard"))

            else:
                status = "FAILED"

        else:
            status = "FAILED"

        # ❌ FAILED LOG
        cursor.execute(
            "INSERT INTO logs (username, status, time) VALUES (?,?,?)",
            (username, status, datetime.now().isoformat())
        )

        conn.commit()
        conn.close()

        flash("Invalid Credentials!")

    return render_template("login.html")


# ---------------- REGISTER ----------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO users (username,password) VALUES (?,?)",
            (username, hashed)
        )

        conn.commit()
        conn.close()

        flash("Registration successful! Please login.")
        return redirect(url_for("login"))

    return render_template("register.html")


# ---------------- DASHBOARD ----------------

@app.route("/dashboard")
def dashboard():

    if "user" in session:
        return render_template("dashboard.html")

    return redirect(url_for("login"))


# ---------------- VAULT ----------------

@app.route("/vault")
def vault():

    if "user" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE username=?",
        (session["user"],)
    )

    user = cursor.fetchone()

    cursor.execute(
        "SELECT * FROM vault WHERE user_id=?",
        (user["id"],)
    )

    passwords = cursor.fetchall()

    conn.close()

    return render_template("vault.html", passwords=passwords)


# ---------------- ADD PASSWORD ----------------

@app.route("/add_password", methods=["POST"])
def add_password():

    if "user" not in session:
        return redirect(url_for("login"))

    website = request.form.get("website")
    account_username = request.form.get("username")
    password = request.form.get("password")

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE username=?",
        (session["user"],)
    )

    user = cursor.fetchone()

    cursor.execute(
        "INSERT INTO vault (user_id, website, username, password) VALUES (?,?,?,?)",
        (user["id"], website, account_username, password)
    )

    conn.commit()
    conn.close()

    return redirect(url_for("vault"))


# ---------------- LOGOUT ----------------

@app.route("/logout")
def logout():

    session.pop("user", None)
    return redirect(url_for("login"))


# ---------------- PASSWORD GENERATOR ----------------

@app.route("/generator")
def generator():

    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    password = "".join(secrets.choice(alphabet) for _ in range(16))

    return render_template("generator.html", password=password)


# ---------------- LOGS (INTRUSION MONITOR) ----------------

@app.route("/logs")
def logs():

    if "user" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor()

    last_10_min = (datetime.now() - timedelta(minutes=10)).isoformat()

    cursor.execute(
        "SELECT * FROM logs WHERE status='FAILED' AND time >= ? ORDER BY time DESC",
        (last_10_min,)
    )

    logs = cursor.fetchall()
    conn.close()

    return render_template("logs.html", logs=logs)


# ---------------- SETTINGS ----------------

@app.route("/settings")
def settings():

    if "user" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE username=?",
        (session["user"],)
    )

    user = cursor.fetchone()
    conn.close()

    return render_template("settings.html", user=user)


# ---------------- CHANGE PASSWORD ----------------

@app.route("/change-password", methods=["POST"])
def change_password():

    if "user" not in session:
        return redirect(url_for("login"))

    current = request.form.get("current_password")
    new = request.form.get("new_password")

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE username=?",
        (session["user"],)
    )

    user = cursor.fetchone()

    stored_password = user["password"]

    if isinstance(stored_password, str):
        stored_password = stored_password.encode()

    if not bcrypt.checkpw(current.encode(), stored_password):
        flash("Current password is incorrect!")
        return redirect(url_for("settings"))

    new_hashed = bcrypt.hashpw(new.encode(), bcrypt.gensalt())

    cursor.execute(
        "UPDATE users SET password=? WHERE username=?",
        (new_hashed, session["user"])
    )

    conn.commit()
    conn.close()

    flash("Password updated successfully!")
    return redirect(url_for("settings"))


@app.route("/monitor")
def monitor():

    if "user" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor()

    last_10_min = (datetime.now() - timedelta(minutes=10)).isoformat()

    # Total failed attempts
    cursor.execute(
        "SELECT COUNT(*) FROM logs WHERE status='FAILED' AND time >= ?",
        (last_10_min,)
    )
    total_failed = cursor.fetchone()[0]

    # Failed attempts per user
    cursor.execute(
        """
        SELECT username, COUNT(*) as attempts
        FROM logs
        WHERE status='FAILED' AND time >= ?
        GROUP BY username
        ORDER BY attempts DESC
        """,
        (last_10_min,)
    )
    user_attempts = cursor.fetchall()

    # Recent activity
    cursor.execute(
        """
        SELECT * FROM logs
        WHERE time >= ?
        ORDER BY time DESC
        LIMIT 10
        """,
        (last_10_min,)
    )
    recent_logs = cursor.fetchall()

    conn.close()

    return render_template(
        "monitor.html",
        total_failed=total_failed,
        user_attempts=user_attempts,
        recent_logs=recent_logs
    )


# ---------------- RUN SERVER ----------------

if __name__ == "__main__":
    app.run(debug=True)