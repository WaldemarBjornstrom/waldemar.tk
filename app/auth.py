from flask import Blueprint, render_template, redirect, url_for, request, flash, abort
import flask_login
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required
import json
from .models import User
from . import db, is_safe_url

invalid_usernames = ['admin', 'user', 'administrator']

auth = Blueprint('auth', __name__)

@auth.route('/login')
def login():
    return render_template('login.html')

@auth.route('/login', methods=['POST'])
def login_post():
    username = request.form.get('username')
    password = request.form.get('password')
    remember = True if request.form.get('rememberme') else False

    user = User.query.filter_by(username=username).first()

    if not user or not check_password_hash(user.password, password): 
        flash('Please check your login details and try again.')
        return redirect(url_for('auth.login'))

    next = request.args.get('next')
    if not is_safe_url(next):
        return abort(400)

    login_user(user, remember=remember)
    return redirect(next or url_for('main.index'))

@auth.route('/signup')
def signup():
    return render_template('signup.html')

@auth.route('/signup', methods=['POST'])
def signup_post():

    username = request.form.get('username').lower()
    name = request.form.get('name')
    password = request.form.get('password')

    user = User.query.filter_by(username=username).first() 

    if user: 
        flash('User already exists')
        return redirect(url_for('auth.signup'))

    if username != "" and username not in invalid_usernames:
        new_user = User(username=username, name=name, password=generate_password_hash(password, method='sha256'), permission="User")
    else:
        flash('Invalid username')
        return redirect(url_for('auth.signup'))

    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('auth.login'))

@auth.route('/forgot')
def forgot():
    return "Coming up"

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))