from flask import Blueprint, render_template, redirect, url_for, request, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
import json
from .models import User
from . import db
import shutil
from urllib.parse import urlparse, urljoin

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc

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
        new_user = User(username=username, name=name, password=generate_password_hash(password, method='sha256'), permission="User", about="")
    else:
        flash('Invalid username')
        return redirect(url_for('auth.signup'))

    db.session.add(new_user)
    db.session.commit()

    user = User.query.filter_by(username=username).first()
    shutil.copyfile('app/static/user-uploads/default.jpg', 'app/static/user-uploads/' + str(user.id) + 'profilepic.png')
    user.picurl = '/static/user-uploads/' + str(user.id) + 'profilepic.png'
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

@auth.route('/registeradmin')
def registeradmin():
    user = User.query.filter_by(username='admin').first()
    if not user:
        return render_template('configadmin.html')
    else:
        return "Admin user already configured"

@auth.route('/registeradmin', methods=['POST'])
def registeradmin_post():
    user = User.query.filter_by(username='admin').first() 

    if not user:
        username = 'admin'
        name = 'Administrator'
        password = request.form.get('password')
        new_user = User(username=username, name=name, password=generate_password_hash(password, method='sha256'), permission="Administrator")
        db.session.add(new_user)
        db.session.commit()
        user = User.query.filter_by(username='admin').first()
        shutil.copyfile('app/static/user-uploads/default.jpg', 'app/static/user-uploads/' + str(user.id) + 'profilepic.png')
        user.picurl = '/static/user-uploads/' + str(user.id) + 'profilepic.png'
        db.session.commit()
        return redirect(url_for('auth.login'))
    else: 
        flash('Admin user already configured')
        return redirect(url_for('auth.login'))