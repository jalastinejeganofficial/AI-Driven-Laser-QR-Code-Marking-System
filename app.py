from flask import Flask, render_template, request, redirect, url_for, Response
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import mysql.connector
from datetime import datetime, timedelta
from PIL import Image
from pyzbar.pyzbar import decode

app = Flask(__name__)
app.secret_key = 'your_secure_key_here'  # Replace with os.urandom(24) or env var in production

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)

# User class
class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

# DB connection
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="qr_marking_system"
    )

# Load user from DB
@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return User(user[0], user[1], user[2])
    return None

# Home route → redirect based on role
@app.route("/")
def home():
    if current_user.is_authenticated:
        if current_user.role == "admin":
            return redirect("/admin-dashboard")
        elif current_user.role == "user":
            return redirect("/user-dashboard")
    return redirect("/login")

# Login page
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password, role FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and password == user[2]:  # Replace with hashed check later
            login_user(User(user[0], user[1], user[3]))
            return redirect("/")
        else:
            return "❌ Invalid credentials"
    return render_template("login.html")

# Logout
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/login")

# Admin dashboard
@app.route("/admin-dashboard")
@login_required
def admin_dashboard():
    if current_user.role != "admin":
        return "⛔ Access denied"
    return render_template("admin_dashboard.html")

# Admin: View all records
@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    if current_user.role != "admin":
        return "⛔ Access denied"

    conn = get_db_connection()
    cursor = conn.cursor()
    query = "SELECT id, item, vendor, lot, supply_date, warranty, inspection_status, location FROM track_fittings"
    filters = []
    conditions = []

    if request.method == "POST":
        vendor = request.form.get("vendor")
        status = request.form.get("inspection_status")
        if vendor:
            conditions.append("vendor = %s")
            filters.append(vendor)
        if status:
            conditions.append("inspection_status = %s")
            filters.append(status)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)

    cursor.execute(query, filters)
    records = cursor.fetchall()
    conn.close()
    return render_template("dashboard.html", records=records)

# Admin: Edit entry
@app.route("/edit/<int:entry_id>", methods=["GET", "POST"])
@login_required
def edit_entry(entry_id):
    if current_user.role != "admin":
        return "⛔ Access denied"

    conn = get_db_connection()
    cursor = conn.cursor()
    if request.method == "POST":
        data = (
            request.form["item"],
            request.form["vendor"],
            request.form["lot"],
            request.form["supply_date"],
            request.form["warranty"],
            request.form["inspection_status"],
            request.form["location"],
            entry_id
        )
        cursor.execute("""
            UPDATE track_fittings
            SET item=%s, vendor=%s, lot=%s, supply_date=%s,
                warranty=%s, inspection_status=%s, location=%s
            WHERE id=%s
        """, data)
        conn.commit()
        conn.close()
        return "✅ Entry updated successfully. <a href='/dashboard'>Go back</a>"

    cursor.execute("SELECT * FROM track_fittings WHERE id = %s", (entry_id,))
    record = cursor.fetchone()
    conn.close()
    return render_template("edit_entry.html", record=record)

# Admin: AI report
@app.route("/ai-report")
@login_required
def ai_report():
    if current_user.role != "admin":
        return "⛔ Access denied"

    conn = get_db_connection()
    cursor = conn.cursor()
    cutoff_date = (datetime.now() - timedelta(days=730)).strftime("%Y-%m-%d")
    cursor.execute("""
        SELECT item, vendor, lot, supply_date, inspection_status
        FROM track_fittings
        WHERE supply_date <= %s AND inspection_status = 'Pending'
    """, (cutoff_date,))
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        report = "✅ All fittings are within warranty and inspection timelines."
    else:
        report = "🚨 AI Report: Items Needing Attention\n\n"
        for row in rows:
            report += f"- {row[0]} from {row[1]} (Lot {row[2]}) supplied on {row[3]} is still marked as '{row[4]}'.\n"
    return render_template("ai_report.html", report=report)

# Admin: Export CSV
@app.route("/export")
@login_required
def export_csv():
    if current_user.role != "admin":
        return "⛔ Access denied"

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, item, vendor, lot, supply_date, warranty, inspection_status, location FROM track_fittings")
    rows = cursor.fetchall()
    conn.close()

    def generate():
        yield "ID,Item,Vendor,Lot,Supply Date,Warranty,Inspection,Location\n"
        for row in rows:
            formatted_row = [str(col).replace(',', ' ') if col else '' for col in row]
            yield ",".join(formatted_row) + "\n"

    return Response(generate(), mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=qr_metadata.csv"})

# User dashboard → redirect to scan/upload
@app.route("/user-dashboard")
@login_required
def user_dashboard():
    if current_user.role != "user":
        return "⛔ Access denied"
    return redirect("/user-scan-upload")

# User: Scan + Upload page
@app.route("/user-scan-upload", methods=["GET", "POST"])
@login_required
def user_scan_upload():
    if current_user.role != "user":
        return "⛔ Access denied"
    return render_template("user_scan_upload.html")

# User: Upload QR image
@app.route("/upload-qr", methods=["POST"])
@login_required
def upload_qr():
    if current_user.role != "user":
        return "⛔ Access denied"
    file = request.files["qr_image"]
    img = Image.open(file.stream)
    decoded = decode(img)
    if decoded:
        qr_data = decoded[0].data.decode("utf-8")
        return redirect(f"/view-details?code={qr_data}")
    return "❌ QR code not detected."

# User: View metadata
@app.route("/view-details")
@login_required
def view_details():
    if current_user.role != "user":
        return "⛔ Access denied"
    qr_code = request.args.get("code")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT item, vendor, lot, supply_date, warranty, inspection_status, location FROM track_fittings WHERE lot = %s", (qr_code,))
    record = cursor.fetchone()
    conn.close()
    if not record:
        return "❌ No matching record found."
    return render_template("view_details.html", record=record)

# Run the app
if __name__ == "__main__":
    app.run(debug=True)