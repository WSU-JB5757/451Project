from flask import Flask, render_template, request, redirect, url_for, session
import oracledb
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "key"

# =========================================================
# ORACLE THIN CONNECTION
# =========================================================
def get_connection():
    return oracledb.connect(
        user="system",
        password="password_here",
        dsn="localhost:see other"
    )

# =========================================================
# HOME ROUTE
# =========================================================
@app.route('/')
def home():
    return redirect(url_for('login'))

# =========================================================
# LOGIN
# =========================================================
@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        username = request.form.get('username')
        password = request.form.get('password')

        conn = get_connection()

        try:
            with conn.cursor() as cursor:

                cursor.execute("""
                    SELECT user_id, first_name, last_name, password_hash, role
                    FROM PROJECTUSERREV
                    WHERE first_name = :first_name
                """, {"first_name": username})

                user = cursor.fetchone()

                if not user:
                    return render_template("login.html", error="User not found")

                user_id, first_name, last_name, password_hash, role = user

                if not check_password_hash(password_hash, password):
                    return render_template("login.html", error="Invalid password")

                session['user_id'] = user_id
                session['role'] = role

                if role == "admin":
                    return redirect(url_for("admin_dashboard"))
                else:
                    return redirect(url_for("user_dashboard"))

        finally:
            conn.close()

    return render_template("login.html")

# =========================================================
# USER DASHBOARD
# =========================================================
@app.route('/user')
def user_dashboard():

    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_connection()

    try:
        with conn.cursor() as cursor:

            # USER INFO
            cursor.execute("""
                SELECT first_name, last_name
                FROM PROJECTUSERREV
                WHERE user_id = :user_id
            """, {"user_id": session['user_id']})

            user = cursor.fetchone()

            if not user:
                return "User not found"

            # EMAILS
            cursor.execute("""
                SELECT email
                FROM PROJECTEMAILREV
                WHERE user_id = :user_id
            """, {"user_id": session['user_id']})

            emails = [row[0] for row in cursor.fetchall()]

        return render_template(
            "user_dashboard.html",
            first_name=user[0],
            last_name=user[1],
            emails=emails
        )

    finally:
        conn.close()

# =========================================================
# ADMIN DASHBOARD
# =========================================================
@app.route('/admin')
def admin_dashboard():

    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    return render_template("admin_dashboard.html")

# =========================================================
# CREATE USER
# =========================================================
@app.route('/create_user', methods=['GET', 'POST'])
def create_user():

    if request.method == 'POST':

        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        password = request.form.get('password')

        emails = [e for e in request.form.getlist('emails[]') if e.strip()]
        socials = [s for s in request.form.getlist('socials[]') if s.strip()]

        if not first_name or not last_name or not password:
            return render_template("create_user.html", error="Missing required fields")

        if len(emails) == 0:
            return render_template("create_user.html", error="At least one email required")

        hashed_password = generate_password_hash(password)

        # SAFE UNIQUE ID GENERATION
        user_id = abs(hash(first_name + emails[0])) % 1000000000

        conn = get_connection()

        try:
            with conn.cursor() as cursor:

                # INSERT USER
                cursor.execute("""
                    INSERT INTO PROJECTUSERREV
                    (user_id, first_name, last_name, password_hash, role)
                    VALUES (:user_id, :first_name, :last_name, :password_hash, 'user')
                """, {
                    "user_id": user_id,
                    "first_name": first_name,
                    "last_name": last_name,
                    "password_hash": hashed_password
                })

                # INSERT EMAILS
                for email in emails:
                    cursor.execute("""
                        INSERT INTO PROJECTEMAILREV
                        (user_id, email)
                        VALUES (:user_id, :email)
                    """, {
                        "user_id": user_id,
                        "email": email
                    })

                # INSERT SOCIAL MEDIA
                for social in socials:
                    cursor.execute("""
                        INSERT INTO PROJECTSOCIALMEDIAREV
                        (user_id, socialmedia)
                        VALUES (:user_id, :socialmedia)
                    """, {
                        "user_id": user_id,
                        "socialmedia": social
                    })

            conn.commit()

            session['user_id'] = user_id
            session['role'] = 'user'

            return redirect(url_for('user_dashboard'))

        except Exception as e:
            conn.rollback()
            return render_template("create_user.html", error=str(e))

        finally:
            conn.close()

    return render_template("create_user.html")

# =========================================================
# LOGOUT
# =========================================================
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# =========================================================
# RUN APP
# =========================================================
if __name__ == "__main__":
    app.run(debug=True)