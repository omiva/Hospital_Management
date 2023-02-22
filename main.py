from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, login_required, logout_user, LoginManager, login_manager, current_user
from werkzeug.security import generate_password_hash, check_password_hash

import MySQLdb
import requests
import django
import enchant
from django import template

# my DB connection
local_server = True
app = Flask(__name__)
app.secret_key = 'BAAM'

# for getting unique user access
login_manager = LoginManager(app)
login_manager.login_view = 'log_in'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# app.config['SQLALCHEMY_DATABASE_URL']='mysql://username:password@localhost/database_table_name'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost/cresearch'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)
# create db model
class Animals(db.Model):
    sl_no = db.Column(db.Integer)
    name = db.Column(db.String(100))
    breed = db.Column(db.String(100))
    animal_id = db.Column(db.Integer, primary_key=True)
    # for test
    # id = db.Column(db.Integer, primary_key=True)
    # name = db.Column(db.String(100))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30))
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(1000))


@app.route('/test')
def hello():
    a = Animals.query.all()
    print(a)
    try:
        Animals.query.all()
        return "Database connected"
    except:
        return "Database not connected"

@app.route('/account')
def account():
    return render_template('account.html')

@app.route('/home')
def test():
    return "this home"

@app.route('/access')
def access():
    # flash("Logout Success", "danger")
    return render_template('access.html')

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/animals')
def animals():
    # if not User.is_authenticated:
        # return render_template('login.html')
    return render_template('animals.html', username=current_user.username)

@app.route('/login', methods=['POST', 'GET'])
def log_in():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash("Logout Successful", "danger")
            return redirect(url_for('access'))
        else:
            flash("Incorrect username or password", "danger")
            return redirect(url_for('log_in'))
    return render_template('login.html')


@app.route('/signup', methods=['POST', 'GET'])
def sign_up():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            flash("Email already exists, please try with a different email", "danger")
            return render_template('signup.html')
        encpass = generate_password_hash(password)

        # method 1-
        new_user = db.engine.execute(f"INSERT INTO `user` (`username`, `email`, `password`) VALUES ('{username}' ,'{email}','{encpass}')")
        return render_template("login.html")

        # method 2-(not working)
        # newuser = User(username=username, email=email, password=encpass)
        # db.session(newuser)
        # db.session.commit()
    return render_template('signup.html')

@app.route('/logout')
@login_required
def log_out():
    logout_user()
    return redirect(url_for('log_in'))


app.run(debug=True)
