from flask import Flask, render_template, request, redirect, session, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os

# -------------------- APP CONFIG --------------------

app = Flask(__name__)

app.config['SECRET_KEY'] = 'supersecuredevsecopskey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = 'uploads'

db = SQLAlchemy(app)

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

        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

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

        # AUTO ADMIN CREATION
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
def login():

    if request.method == 'POST':

        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(
            email=email
        ).first()

        if user and check_password_hash(
            user.password,
            password
        ):

            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role

            flash(
                "Login Successful!",
                "success"
            )

            # ROLE BASED LOGIN
            if user.role == 'admin':
                return redirect('/dashboard')

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

    # SESSION PROTECTION
    if 'user_id' not in session:

        flash(
            "Please login first!",
            "warning"
        )

        return redirect('/login')

    # ADD TASK
    if request.method == 'POST':

        title = request.form['title']
        description = request.form['description']

        file = request.files['file']

        filename = ""

        if file and file.filename != "":

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

    # ADMIN CAN SEE ALL TASKS
    if session['role'] == 'admin':

        tasks = Task.query.all()

    # USER CAN SEE OWN TASKS
    else:

        tasks = Task.query.filter_by(
            user_id=session['user_id']
        ).all()

    # STATS
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

    # USER SECURITY
    if session['role'] != 'admin':

        if task.user_id != session['user_id']:

            flash(
                "Unauthorized Access!",
                "danger"
            )

            return redirect('/dashboard')

    if request.method == 'POST':

        task.title = request.form['title']

        task.description = request.form['description']

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

    # USER SECURITY
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
        debug=True
    )