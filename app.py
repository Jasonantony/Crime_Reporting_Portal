from flask import Flask, render_template, request, redirect, session, url_for, flash
import os
from werkzeug.utils import secure_filename
from datetime import datetime
import mysql.connector
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user

# upload configure

# Initialize Flask app


app=Flask(__name__)
app.secret_key = 'Melrin@joyce'  # Use a strong random key in production
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit

# database configuration
# MySQL config
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Merlin@09'
app.config['MYSQL_DB'] = 'user_portal'

mysql = MySQL(app)
bcrypt = Bcrypt(app)
# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User class for login
class User(UserMixin):
    def __init__(self, id, email):
        self.id = id
        self.email = email

    def get_id(self):
        return str(self.id)


@login_manager.user_loader
def load_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, email FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()
    if user:
        return User(user[0], user[1])
    return None

# Home route
@app.route('/')
def home():
    
    return render_template('index.html')

# report route
@app.route('/report')
def report():
    return render_template('report.html')

# about route
@app.route('/about')
def about():
    testimonials = [
        "Quick action saved my son during a kidnapping attempt. Thanks TN Police!",
        "Online scam recovered within 48 hours. Unbelievable work.",
        "The officers were kind, responsive, and diligent.",
        "Cyber Crime Cell helped track down an Instagram stalker.",
        "Never thought a stolen phone would be found—TN Police did it!",
        "Women helpline support is fast and very helpful.",
        "Police patrolling has made our street much safer.",
        "My faith in law enforcement is restored—great job on burglary case!"
    ]
    return render_template('about.html', testimonials=testimonials)


# login page route
@app.route('/signin')
def signin():
    return render_template('login.html')


# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        print(f"Received login attempt for email: {email}")

        cur = mysql.connection.cursor()
        cur.execute("SELECT id, password FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()

        if user and bcrypt.check_password_hash(user[1], password):
            print("Login successful. Redirecting to dashboard...")
            user_obj = User(user[0], email)
            login_user(user_obj)
            session['user_id'] = user[0]
            session['email'] = email
            if email == 'admin@crb.com':
                flash("Welcome Admin!", "success")
                return redirect(url_for('dashboard_admin'))
            else:
                flash("Login successful!", "success")
                return redirect(url_for('dashboard'))
        else:
            print("Login failed.")
            flash("Invalid email or password", "danger")
    
    return render_template('login.html')


# user_Dashboard route
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard_user.html', email=current_user.email)

# Admin Dashboard route
@app.route('/dashboard_admin')
@login_required
def dashboard_admin():
    
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, user_id, title, description, date_created FROM complaints ORDER BY date_created DESC")
    complaints = cur.fetchall()
    cur.close()

    return render_template("dashboard_police.html", complaints=complaints)

# submit report route
@app.route('/submit_report', methods=['POST'])
@login_required
def submit_report():
    try:
        # Get form data
        name = request.form.get("name")
        contact = request.form.get("contact")
        incident_type = request.form.get("incidentType")
        incident_date = request.form.get("incidentDate")
        incident_time = request.form.get("incidentTime")
        region = request.form.get("region")
        station = request.form.get("station")
        description = request.form.get("description")
        has_evidence = 1 if request.form.get("evidenceOption") == "Yes" else 0

        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        title = f"{incident_type} in {region}"

        # Insert initial record
        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO complaints (user_id, title, description, date_created)
            VALUES (%s, %s, %s, %s)
        """, (
            contact, title, description, now
        ))
        mysql.connection.commit()

        # Get inserted ID
        caseid = cur.lastrowid

        # Handle file upload if exists
        evidence_file = None
        if "evidenceFile" in request.files:
            file = request.files["evidenceFile"]
            if file and file.filename != '':
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                evidence_file = filename

        # Update with remaining details
        cur.execute("""
    INSERT INTO complaints (
        user_id, title, description, date_created,
        name, contact, incident_type, incident_date, incident_time,
        region, station, has_evidence, evidence_file, submitted_at
    )
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
""", (
    contact,  # using contact as user_id
    f"{incident_type} in {region}",
    description,
    now,
    name,
    contact,
    incident_type,
    incident_date,
    incident_time,
    region,
    station,
    1 if request.form.get("evidenceOption") == "Yes" else 0,
    request.files["evidenceFile"].filename if "evidenceFile" in request.files else None,
    now
))

        mysql.connection.commit()
        cur.close()

        return render_template("report_success.html", caseid=caseid)

    except Exception as e:
        print("Error:", e)
        flash("Something went wrong!", "danger")
        return redirect("/report")
# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('login'))



# register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password_raw = request.form.get('password')

        if not name or not email or not password_raw:
            flash("Please fill in all fields.")
            return render_template('login.html')  # Stay on the same page if form is incomplete

        password = bcrypt.generate_password_hash(password_raw).decode('utf-8')

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", (name, email, password))
        mysql.connection.commit()
        cur.close()

        flash("Registration successful! Please login.")
        return redirect(url_for('dashboard'))  # Redirect to login page after successful registration

    # return render_template('login.html')  # Show the registration form on GET request

if __name__ == "__main__":
    app.run(debug=True)
