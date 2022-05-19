from flask import Blueprint, render_template, redirect, url_for, request, flash, abort
from sqlalchemy import false
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
import json, random, string, shutil
from .models import User
from . import db, github
from urllib.parse import urlparse, urljoin

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc

def generate_salt():
    letters = string.ascii_letters + string.digits + string.punctuation
    salt = ''.join(random.choice(letters) for i in range(10))
    return salt

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

    if not user or not check_password_hash(user.password, user.salt + password): 
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
    password2 = request.form.get('password2')

    user = User.query.filter_by(username=username).first() 

    if user: 
        flash('User already exists')
        return redirect(url_for('auth.signup'))

    if password2 != password:
        flash('Password do not match')
        return redirect(url_for('auth.signup'))

    if username != "" and username not in invalid_usernames:
        salt = generate_salt()
        new_user = User(username=username, name=name, password=generate_password_hash(salt + password, method='sha256'), salt=salt, permission="User", about="")
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
        salt = generate_salt()
        new_user = User(username=username, name=name, password=generate_password_hash(salt + password, method='sha256'), salt=salt, permission="Administrator", about="")
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

@auth.route('/callback')
@github.authorized_handler
def callback(oauth_token):
    next_url = request.args.get('next') or url_for('main.index')
    if oauth_token is None:
        flash('Authorization failed.')
        return redirect(next_url)

    response = github.raw_request('GET', 'user', access_token=oauth_token)
    content_type = response.headers.get('Content-Type', '')
    if content_type == 'application/json' or content_type.startswith('application/json;'):
        result = response.json()
        while false and response.links.get('next'):
            url = response.links['next']['url']
            response = github.raw_request('GET', url, access_token=oauth_token)
            if not 200 <= response.status_code <= 299 or \
                not content_type == 'application/json' or content_type.startswith('application/json;'):
                raise Exception('Unexpected response')
            body = response.json()
            if isinstance(body, list):
                result += body
            elif isinstance(body, dict):
                result['items'] += body['items']
            else:
                raise Exception('Unexpected response')
        response = result

    if not current_user.is_authenticated:
        user = User.query.filter_by(github_user_id=response['id']).first()
        if not user:
            flash('No user with that github account linked was found. Either create a new account with github or link your github account to an existing user.')
            return redirect(url_for('auth.login'))
        user.github_oauth = oauth_token
        db.session.commit()
        login_user(user)
        return redirect(next_url)
    elif current_user.is_authenticated:
        user = User.query.filter_by(github_user_id=response['id']).first()
        if not user:
            user = User.query.filter_by(username=current_user.username).first()
            if not user:
                raise(500)
            user.github_oauth = oauth_token
            user.github_user_id = response['id']
            db.session.commit()
        else:
            flash('You already have this github account linked to this site. Try logging in instead.')
        return redirect(url_for('main.editprofile'))

@github.access_token_getter
def token_getter():
    user = User.query.filter_by(github_user_id=current_user.github_user_id).first()
    if user is not None:
        return user.github_oauth
        
@auth.route('/github/login')
def github_login():
    return github.authorize()

