import os

from werkzeug.utils import secure_filename

import bcrypt
import os
from flask import Flask, render_template, request, redirect,session

def login():

    if request.method == 'POST':

        email = request.form['email']

        password = request.form['password']

        user = User.query.filter_by(
            email=email
        ).first()

        if user and bcrypt.checkpw(
            password.encode('utf-8'),
            user.password.encode('utf-8')
        ):

           session['user']=user.email
           return redirect('/dashboard')

        else:

            return "Invalid Credentials"

    return render_template('login.html')
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

app.config['UPLOAD_FOLDER'] = 'uploads'

app.config['SECRET_KEY'] = 'secret123'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db = SQLAlchemy(app)

# User Table
class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(100))

    email = db.Column(db.String(100))

    password = db.Column(db.String(100))


# Task Table
class Task(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    title = db.Column(db.String(200))

    description = db.Column(db.String(500))


# Home Page
@app.route('/')

def home():

    return render_template('index.html')


# Register Page
@app.route('/register', methods=['GET', 'POST'])

def register():

    if request.method == 'POST':

        username = request.form['username']

        email = request.form['email']

        password = request.form['password']

        hashed_password = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()
        )

        user = User(
            username=username,
            email=email,
            password=hashed_password.decode('utf-8')
        )

        db.session.add(user)

        db.session.commit()

        return redirect('/login')

    return render_template('register.html')

# Login Page
@app.route('/login', methods=['GET', 'POST'])

def login():

    if request.method == 'POST':

        email = request.form['email']

        password = request.form['password']

        user = User.query.filter_by(
            email=email
        ).first()

        if user and bcrypt.checkpw(
            password.encode('utf-8'),
            user.password.encode('utf-8')
        ):

            session['user'] = user.email

            return redirect('/dashboard')

        else:

            return "Invalid Credentials"

    return render_template('login.html')
@app.route('/logout')

# Logout page

def logout():
    session.pop(' user ', None)
    return redirect('/login')

# Dashboard Page
@app.route('/dashboard', methods=['GET', 'POST'])

def dashboard():

    if 'user' not in session:

        return redirect('/login')

    if request.method == 'POST':

        title = request.form['title']

        description = request.form['description']

        file = request.files['file']

        filename = ""

        if file:

            filename = secure_filename(file.filename)

            file.save(
                os.path.join(
                    app.config['UPLOAD_FOLDER'],
                    filename
                )
            )

        task = Task(
            title=title,
            description=description
        )

        db.session.add(task)

        db.session.commit()

    tasks = Task.query.all()

    return render_template(
        'dashboard.html',
        tasks=tasks
    )
@app.route('/delete/<int:id>')

def delete(id):

    task = Task.query.get(id)

    db.session.delete(task)

    db.session.commit()

    return redirect('/dashboard')

@app.route('/edit/<int:id>', methods=['GET', 'POST'])

def edit(id):

    task = Task.query.get(id)

    if request.method == 'POST':

        task.title = request.form['title']

        task.description = request.form['description']

        db.session.commit()

        return redirect('/dashboard')

    return render_template(
        'edit.html',
        task=task
    )


if __name__ == '__main__':

    with app.app_context():

        db.create_all()

    app.run(debug=True)