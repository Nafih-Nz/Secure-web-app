from flask import Flask, render_template, request, redirect, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv
from datetime import datetime, timedelta
import jwt
import os

# -------------------- LOAD ENV --------------------

load_dotenv()

# -------------------- APP CONFIG --------------------

app = Flask(__name__)

# -------------------- SECURITY --------------------

csrf = CSRFProtect(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["10 per minute"]
)

app.config["RATELIMIT_STORAGE_URI"] = "memory://"

app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")

jwt_secret = os.getenv("JWT_SECRET")

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")

app.config['UPLOAD_FOLDER'] = 'uploads'

app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

app.permanent_session_lifetime = timedelta(minutes=30)

# -------------------- DATABASE --------------------

db = SQLAlchemy(app)

# -------------------- FILE SECURITY --------------------

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}

def allowed_file(filename):

    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# -------------------- SECURITY HEADERS --------------------

@app.after_request
def security_headers(response):

    response.headers['X-Content-Type-Options'] = 'nosniff'

    response.headers['X-Frame-Options'] = 'SAMEORIGIN'

    response.headers['X-XSS-Protection'] = '1; mode=block'

    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    response.headers['Server'] = 'SecureServer'

    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:;"
    )

    response.headers['Strict-Transport-Security'] = (
        'max-age=31536000; includeSubDomains'
    )

    response.headers["Cache-Control"] = (
        "no-cache, no-store, must-revalidate"
    )

    response.headers["Pragma"] = "no-cache"

    response.headers["Expires"] = "0"

    return response
# -------------------- DATABASE MODELS --------------------

class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(100),
        nullable=False
    )

    email = db.Column(
        db.String(100),
        unique=True,
        nullable=False
    )

    password = db.Column(
        db.String(200),
        nullable=False
    )

    role = db.Column(
        db.String(20),
        default='user'
    )

class Task(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    title = db.Column(
        db.String(200),
        nullable=False
    )

    description = db.Column(
        db.Text,
        nullable=False
    )

    filename = db.Column(
        db.String(200)
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id')
    )

# -------------------- HOME --------------------

@app.route('/')
def home():

    return render_template('index.html')

# -------------------- REGISTER --------------------

@app.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':

        username = request.form['username'].strip()

        email = request.form['email'].strip().lower()

        password = request.form['password']

        # PASSWORD VALIDATION

        if len(password) < 8:

            flash(
                "Password must be at least 8 characters!",
                "danger"
            )

            return redirect('/register')

        existing_user = User.query.filter_by(
            email=email
        ).first()

        if existing_user:

            flash(
                "User already exists!",
                "danger"
            )

            return redirect('/register')

        hashed_password = generate_password_hash(password)

        # ROLE

        role = 'user'

        if email == "admin@gmail.com":
            role = 'admin'

        new_user = User(
            username=username,
            email=email,
            password=hashed_password,
            role=role
        )

        db.session.add(new_user)

        db.session.commit()

        flash(
            "Registration Successful!",
            "success"
        )

        return redirect('/login')

    return render_template('register.html')

# -------------------- LOGIN --------------------

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():

    if request.method == 'POST':

        email = request.form['email'].strip().lower()

        password = request.form['password']

        user = User.query.filter_by(
            email=email
        ).first()

        if user and check_password_hash(
            user.password,
            password
        ):

            session.permanent = True

            session['user_id'] = user.id

            session['username'] = user.username

            session['role'] = user.role

            token = jwt.encode(
                {
                    "user": user.email,
                    "role": user.role,
                    "exp": datetime.utcnow() + timedelta(hours=1)
                },
                jwt_secret,
                algorithm="HS256"
            )

            print(token)

            flash(
                "Login Successful!",
                "success"
            )

            return redirect('/dashboard')

        else:

            flash(
                "Invalid Email or Password",
                "danger"
            )

            return redirect('/login')

    return render_template('login.html')

# -------------------- DASHBOARD --------------------

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():

    if 'user_id' not in session:

        flash(
            "Please login first!",
            "warning"
        )

        return redirect('/login')

    # ADD TASK

    if request.method == 'POST':

        title = request.form['title'].strip()

        description = request.form['description'].strip()

        file = request.files.get('file')

        filename = ""

        if file and file.filename != "" and allowed_file(file.filename):

            filename = secure_filename(
                file.filename
            )

            os.makedirs(
                app.config['UPLOAD_FOLDER'],
                exist_ok=True
            )

            file.save(
                os.path.join(
                    app.config['UPLOAD_FOLDER'],
                    filename
                )
            )

        new_task = Task(
            title=title,
            description=description,
            filename=filename,
            user_id=session['user_id']
        )

        db.session.add(new_task)

        db.session.commit()

        flash(
            "Task Added Successfully!",
            "success"
        )

        return redirect('/dashboard')

    # ADMIN

    if session['role'] == 'admin':

        tasks = Task.query.all()

    else:

        tasks = Task.query.filter_by(
            user_id=session['user_id']
        ).all()

    total_tasks = Task.query.count()

    total_users = User.query.count()

    return render_template(

        'dashboard.html',

        tasks=tasks,

        total_tasks=total_tasks,

        total_users=total_users,

        username=session['username'],

        role=session['role']
    )

# -------------------- EDIT TASK --------------------

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit(id):

    if 'user_id' not in session:

        return redirect('/login')

    task = Task.query.get_or_404(id)

    if session['role'] != 'admin':

        if task.user_id != session['user_id']:

            flash(
                "Unauthorized Access!",
                "danger"
            )

            return redirect('/dashboard')

    if request.method == 'POST':

        task.title = request.form['title'].strip()

        task.description = request.form['description'].strip()

        db.session.commit()

        flash(
            "Task Updated Successfully!",
            "info"
        )

        return redirect('/dashboard')

    return render_template(
        'edit.html',
        task=task
    )

# -------------------- DELETE TASK --------------------

@app.route('/delete/<int:id>')
def delete(id):

    if 'user_id' not in session:

        return redirect('/login')

    task = Task.query.get_or_404(id)

    if session['role'] != 'admin':

        if task.user_id != session['user_id']:

            flash(
                "Unauthorized Access!",
                "danger"
            )

            return redirect('/dashboard')

    db.session.delete(task)

    db.session.commit()

    flash(
        "Task Deleted Successfully!",
        "warning"
    )

    return redirect('/dashboard')

# -------------------- LOGOUT --------------------

@app.route('/logout')
def logout():

    session.clear()

    flash(
        "Logged Out Successfully!",
        "info"
    )

    return redirect('/login')

# -------------------- MAIN --------------------

if __name__ == '__main__':

    with app.app_context():

        db.create_all()

    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False
    )