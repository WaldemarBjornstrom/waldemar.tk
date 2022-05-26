from flask import Blueprint, render_template, redirect, url_for, request, flash, abort
from sqlalchemy import false
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from flask_mail import Message
from datetime import datetime
import json, random, string, shutil, os, pyotp
from .models import User, QueryUser
from . import db, github, mail
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

def generate_hash():
    letters = string.ascii_letters + string.digits
    salt = ''.join(random.choice(letters) for i in range(25))
    return salt

def password_check(passwd):
      
    SpecialSym =['!', '"', '#', '¤', '%', '/', '(', ')', '=', '?', '*', '+', '@', '£', '$', '€', '{', '}', '[', ']', '|', '\\', '^', '~', ';', ':', '<', '>', '.', ',']
    val = True
    msg = ''
      
    if len(passwd) < 8:
        msg += "Password must be at least 8 characters long. "
        val = False
          
    if len(passwd) > 80:
        msg += 'Length should be not be greater than 80. '
        val = False
          
    if not any(char.isdigit() for char in passwd):
        msg += 'Password should have at least one numeral. '
        val = False
          
    if not any(char.isupper() for char in passwd):
        msg += 'Password should have at least one uppercase letter.     '
        val = False

    if not any(char.islower() for char in passwd):
        msg += 'Password should have at least one lowercase letter. '
        val = False
          
    if not any(char in SpecialSym for char in passwd):
        msg += 'Password should have at least one special character. '
        val = False

    if val:
        print('Password is valid.')
        return val
    else: 
        print(msg)
        return msg
          

invalid_usernames = json.loads(open('app/word.json').read())
sender = ('Waldemar.tk', 'no-reply@waldemar.tk')

auth = Blueprint('auth', __name__)

@auth.route('/login')
def login():
    return render_template('login.html')

@auth.route('/login', methods=['POST'])
def login_post():
    username = request.form.get('username')
    password = request.form.get('password')
    remember = True if request.form.get('rememberme') else False

    user = QueryUser.by_username_or_email(username.lower())

    if not user or not check_password_hash(user.password, user.salt + password): 
        flash('Please check your login details and try again.')
        return redirect(url_for('auth.login'))

    next = request.args.get('next')
    if not is_safe_url(next):
        return abort(400)

    if len(password) == 4 and password.isdigit():
        login_user(user, remember=remember)
        return redirect(url_for('auth.change_password', old=password))

    if user.data2 != None:
        userdict = json.loads(user.data2)
    else: 
        flash('Your account is not activated yet. Please check your email.')
        return redirect(url_for('auth.login'))

    if userdict['is_active'] == False:
        flash('Your account is not active yet.')
        return redirect(url_for('auth.login'))

    if '2FA' in userdict and userdict['2FA']['enabled'] == True:
        hashdict = {
            'hash': str(generate_hash()),
            'time': str(datetime.now()),
            'action': '2FA'
        }
        user.data1 = json.dumps(hashdict)
        db.session.commit()
        return redirect(os.environ['URL'] + '/2FA/auth?id=' + str(user.id) + '&hash=' + hashdict['hash'])

    login_user(user, remember=remember)
    return redirect(next or url_for('main.index'))

@auth.route('/signup')
def signup():
    return render_template('signup.html')

@auth.route('/signup', methods=['POST'])
def signup_post():

    username = request.form.get('username').lower()
    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')
    password2 = request.form.get('password2')

    user = QueryUser.by_username(username)

    if user: 
        flash('User already exists')
        return redirect(url_for('auth.signup'))

    user = QueryUser.by_email(email)

    if user:
        flash('Email address already signed up')
        return redirect(url_for('auth.signup'))

    if password2 != password:
        flash('Password do not match')
        return redirect(url_for('auth.signup'))

    if username != "" and username not in invalid_usernames:
        salt = generate_salt()
        new_user = User(username=username, name=name, email=email.lower(), password=generate_password_hash(salt + password, method='sha256'), salt=salt, permission="User", about="")
    else:
        flash('Invalid username')
        return redirect(url_for('auth.signup'))

    db.session.add(new_user)
    db.session.commit()

    user = User.query.filter_by(username=username).first()
    shutil.copyfile('app/static/user-uploads/default.jpg', 'app/static/user-uploads/' + str(user.id) + 'profilepic.png')
    user.picurl = '/static/user-uploads/' + str(user.id) + 'profilepic.png'
    hash = generate_hash()
    hashdict = {
        'hash': hash,
        'time': str(datetime.now()),
        'action': 'activate'
    }
    user.data1 = json.dumps(hashdict)
    db.session.commit()

    link = os.environ['URL'] + '/activate?id=' + str(user.id) + '&hs=' + hash

    db.session.commit()
    msg = Message('Account activation', recipients=[user.email], sender=sender)
    msg.html = render_template('email/activate.html', name=user.name, link=link)
    mail.send(msg)
    flash('Please check your email to activate your account.')
    return redirect(url_for('auth.login'))

@auth.route('/activate')
def activate():
    id = request.args.get('id')
    hash = request.args.get('hs')

    user = User.query.filter_by(id=id).first()
    if not user:
        flash('Invalid link')
        return redirect(url_for('auth.login'))

    if user.data1 != None:
        hashdict = json.loads(user.data1)
    else:
        flash('Your account is already activated.')
        return redirect(url_for('auth.login'))

    if hashdict['action'] != 'activate':
        flash('Invalid link')
        return redirect(url_for('auth.register'))

    if hashdict['hash'] != hash:
        flash('Invalid link')
        return redirect(url_for('auth.register'))

    then = datetime.strptime(hashdict['time'], "%Y-%m-%d %H:%M:%S.%f")
    delta = datetime.now() - then
    deltahours = delta.total_seconds() / 3600

    if deltahours > 24:
        db.session.delete(user)
        flash('Link expired')
        return redirect(url_for('auth.signup'))

    userdict = {
        'is_active': True
    }

    user.data2 = json.dumps(userdict)
    user.data1 = None
    db.session.commit()
    flash('Account activated')
    return redirect(url_for('auth.login'))

@auth.route('/forgot')
def forgot():
    return render_template('forgot.html')

@auth.route('/forgot', methods=['POST'])
def forgot_post():
    email = request.form.get('email')
    user = User.query.filter_by(email=email).first()

    if not user:
        flash('User does not exist')
        return redirect(url_for('auth.forgot'))
    
    hash = generate_hash()
    now = datetime.now()
    hashdict = {'hash': hash, 'time': str(now), 'action': 'reset'}
    user.data1 = json.dumps(hashdict)
    db.session.commit()

    link = os.environ['URL'] + '/reset?id=' + str(user.id) + '&hs=' + hash

    msg = Message('Password Reset', sender=sender, recipients=[user.email])
    msg.html = render_template('email/reset.html', link=link, username=user.username)
    mail.send(msg)
    flash('Check your email for the password reset link.')
    return redirect(url_for('auth.login'))

@auth.route('/reset')
def reset():
    id = request.args.get('id')
    hash = request.args.get('hs')
    user = User.query.filter_by(id=id).first()
    
    if not user:
        flash('Invalid link')
        return redirect(url_for('auth.login'))

    data = json.loads(user.data1)

    if data['action'] != 'reset':
        flash('Invalid link')
        return redirect(url_for('auth.login'))
    
    then = datetime.strptime(data['time'], "%Y-%m-%d %H:%M:%S.%f")
    delta = datetime.now() - then
    deltaminutes = delta.total_seconds() / 60
    if deltaminutes > 10:
        flash('Link expired')
        return redirect(url_for('auth.login'))

    if data['hash'] != hash:
        flash('Invalid link')
        return redirect(url_for('auth.login'))

    return render_template('reset.html', id=id, hash=hash)

@auth.route('/reset', methods=['POST'])
def reset_post():
    id = request.form.get('id')
    hash = request.form.get('hash')
    password = request.form.get('password')
    password2 = request.form.get('password2')

    user = User.query.filter_by(id=id).first()

    if not user:
        flash('Invalid link')
        return redirect(url_for('auth.login'))

    data = json.loads(user.data1)
    then = datetime.strptime(data['time'], "%Y-%m-%d %H:%M:%S.%f")
    delta = datetime.now() - then
    deltaminutes = delta.total_seconds() / 60
    if deltaminutes > 10:
        flash('Link expired')
        return redirect(url_for('auth.login'))

    if data['hash'] != hash:
        flash('Invalid link')
        return redirect(url_for('auth.login'))

    if password2 != password:
        flash('Passwords do not match')
        return redirect('/reset?id=' + id + '&hs=' + hash)

    if password_check(password) != True:
        flash(password_check(password))
        return redirect('/reset?id=' + id + '&hs=' + hash)

    user.password = generate_password_hash(user.salt + password, method='sha256')
    user.data1 = ""
    db.session.commit()

    return redirect(url_for('auth.login'))

@auth.route('/change_password')
@login_required
def change_password2():
    return render_template('change_password.html', old='')

@auth.route('/change_password', methods=['POST'])
@login_required
def change_password_post():
    password = request.form.get('password')
    password2 = request.form.get('password2')
    oldpassword = request.form.get('oldpassword')

    print(current_user.salt)
    print(oldpassword)
    
    if not check_password_hash(current_user.password, current_user.salt + oldpassword):
        flash('Old password is incorrect')
        return redirect(url_for('auth.change_password2'))

    if password2 != password:
        flash('Password do not match')
        return redirect(url_for('auth.change_password2'))
    
    if password_check(password) != True:
        flash(password_check(password))
        return redirect(url_for('auth.change_password'))

    user = User.query.filter_by(id=current_user.id).first()
    user.password = generate_password_hash(user.salt + password, method='sha256')
    db.session.commit()
    return redirect(url_for('main.index'))

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
        flash('Authorization failed.1')
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

@auth.route('/github/unlink')
@login_required
def unlink():
    user = User.query.filter_by(username=current_user.username).first()
    user.github_oauth = None
    user.github_user_id = None
    db.session.commit()
    return redirect(url_for('main.editprofile'))

@auth.route('/callback/register')
@github.authorized_handler
def github_register_post(oauth_token):
    next_url = request.args.get('next') or url_for('main.index')
    if oauth_token is None:
        flash('Github authorization failed.')
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

    user = User.query.filter_by(username=response['login']).first()
    if user:
        flash('Another account with your username already exists. Please login with your username and password or sign up manually with another username.')
        return redirect(url_for('auth.login'))

    user = User.query.filter_by(github_user_id=response['id']).first()
    if not user:
        username = response['login']
        name = response['name']
        email = response['email']
        id = response['id']
        about = response['bio']
        picurl = response['avatar_url']
        salt = generate_salt()
        new_user = User(username=username, email=email, salt=salt, github_user_id=id, github_oauth=oauth_token, name=name, permission="User", about=about, picurl=picurl)
        db.session.add(new_user)
        db.session.commit()
        user = User.query.filter_by(github_user_id=response['id']).first()
        login_user(user)
        return redirect(url_for('auth.setupgithubregister'))
    
    flash('You already have this github account linked to this site. Try logging in instead.')
    return redirect(url_for('auth.login'))

@auth.route('/setupgithubregister')
@login_required
def setupgithubregister():
    user = User.query.filter_by(username=current_user.username).first()
    if user.email == None:
        return render_template('setupgithubregisteremail.html')
    else:
        return render_template('setupgithubregister.html')

@auth.route('/setupgithubregister', methods=['POST'])
@login_required
def setupgithubregister_post():
    password = request.form.get('password')
    password2 = request.form.get('password2')
    email = request.form.get('email')

    user = User.query.filter_by(username=current_user.username).first()

    if password2 != password:
        flash('Password do not match')
        return redirect(url_for('auth.setupgithubregister'))

    if password == '':
        flash('Password cannot be blank')
        return redirect(url_for('auth.setupgithubregister'))

    if email:
        if QueryUser.by_email(email):
            flash('Email already exists')
            return redirect(url_for('auth.setupgithubregister'))
        user.email = email

    user.password = generate_password_hash(user.salt + password, method='sha256')
    db.session.commit()

    return redirect(url_for('main.profile'))

@github.access_token_getter
def token_getter():
    user = User.query.filter_by(github_user_id=current_user.github_user_id).first()
    if user is not None:
        return user.github_oauth
        
@auth.route('/github/login')
def github_login():
    return github.authorize()

@auth.route('/github/register')
def github_register():
    return github.authorize(scope="user", redirect_uri=url_for('auth.github_register_post', _external=True))

@auth.route('/2FA/setup')
@login_required
def setup2fa():
    user = User.query.filter_by(username=current_user.username).first()
    userdict = json.loads(user.data2)
    if '2FA' in userdict and userdict['2FA']['enabled'] == True:
        state = userdict['2FA']['enabled']
        return render_template('setup2fa.html', secret=userdict['2FA']['secret'], state=state)
    secret = pyotp.random_base32()
    if '2FA' in userdict and 'secret' in userdict['2FA']:
        secret = userdict['2FA']['secret']
    userdict['2FA'] = {'enabled': False, 'secret': secret}
    user.data2 = json.dumps(userdict)
    db.session.commit()
    state = userdict['2FA']['enabled']
    return render_template('setup2fa.html', secret=secret, state=state)

@auth.route('/2FA/activate', methods=['POST'])
@login_required
def enable2fa():
    otp = request.form.get('otp')
    user = User.query.filter_by(username=current_user.username).first()
    userdict = json.loads(user.data2)
    secret = userdict['2FA']['secret']
    if pyotp.TOTP(secret).verify(otp):
        flash('2FA enabled')
        userdict['2FA']['enabled'] = True
        user.data2 = json.dumps(userdict)
        db.session.commit()
        return redirect(url_for('auth.setup2fa'))
    else:
        flash('Invalid OTP')
        return redirect(url_for('auth.setup2fa'))

@auth.route('/2FA/disable', methods=['POST'])
@login_required
def disable2fa():
    otp = request.form.get('otp')
    user = User.query.filter_by(username=current_user.username).first()
    userdict = json.loads(user.data2)
    secret = userdict['2FA']['secret']
    if pyotp.TOTP(secret).verify(otp):
        flash('2FA disabled')
        userdict['2FA']['enabled'] = False
        user.data2 = json.dumps(userdict)
        db.session.commit()
        return redirect(url_for('auth.setup2fa'))
    else:
        flash('Invalid OTP')
        return redirect(url_for('auth.setup2fa'))

@auth.route('/2FA/auth')
def auth2fa():
    hash = request.args.get('hash')
    id = request.args.get('id')
    if hash == None or id == None:
        flash('Invalid request')
        return redirect(url_for('auth.login'))
    return render_template('auth2fa.html', hash=hash, id=id)

@auth.route('/2FA/auth', methods=['POST'])
def auth2fa_POST():
    id = request.form.get('id')
    hash = request.form.get('hash')
    otp = request.form.get('otp')

    print(id)
    print(hash)
    print(otp)

    user = User.query.filter_by(id=id).first()

    if not user:
        flash('Invalid loginuser')
        return redirect(url_for('auth.login'))

    data = json.loads(user.data1)
    then = datetime.strptime(data['time'], "%Y-%m-%d %H:%M:%S.%f")
    delta = datetime.now() - then
    deltaminutes = delta.total_seconds() / 60
    if deltaminutes > 5:
        flash('Login expired')
        return redirect(url_for('auth.login'))

    if data['hash'] != hash:
        flash('Invalid loginhash')
        return redirect(url_for('auth.login'))

    userdict = json.loads(user.data2)
    secret = userdict['2FA']['secret']
    if pyotp.TOTP(secret).verify(otp):
        user.data1 = ""
        db.session.commit()
        login_user(user)
        return redirect(url_for('main.profile'))
    else:
        flash('Invalid OTP')
        return redirect(url_for('auth.auth2fa', hash=hash, id=id))

