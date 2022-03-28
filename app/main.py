from flask import Blueprint, render_template, flash, request, redirect, url_for, send_from_directory, escape, abort
from werkzeug.utils import secure_filename
from flask_login import login_required, current_user
import string    
import random


from app.admin import current
from . import db
from .models import User, API

ALLOWED_EXTENSIONS = {'png', 'jpg'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

main = Blueprint('main', __name__)

@main.route('/')
def index():
    user = User.query.filter_by(username='admin').first()
    if not user:
        return redirect(url_for('auth.registeradmin'))
    return render_template('index.html')

@main.route('/projects')
def projects():
    return render_template('projects/index.html')

@main.route('/projects/SE-Social')
def render_sesocial():
    return render_template('projects/SE-social.html')

@main.route('/profile')
@login_required
def profile():
    username = current_user.username
    user = User.query.filter_by(username=username).first()
    usermenu = '<ul>'
    if current_user.permission == 'Administrator':
        usermenu = usermenu + '<li><a href="' + url_for('admin.admin_page') + '">Admin area</a></li><br>'
    usermenu = usermenu + '<li><a href="' + url_for('main.editprofile') + '">Edit profile</a></li><br><li><a href="/profile/registerapi">Register free API key</a></li><br></ul>'

    role = '<h4>' + current_user.permission + '</h4>'

    return render_template('profile.html', picurl=user.picurl, usermenu=usermenu, role=role, thisuser=current_user.name)

@main.route('/profile/<user>')
def otherprofile(user):
    dbuser = User.query.filter_by(username=user).first()
    if not dbuser:
        abort(404)
    if str(dbuser.about) == 'None':
        about = ''
    else:
        about = str(dbuser.about)
    return render_template('profile.html', picurl=dbuser.picurl, about=about, thisuser=dbuser.name)

@login_required
@main.route('/profile/settings')
def editprofile():
    user = User.query.filter_by(username=current_user.username).first()
    about = user.about
    return render_template('editprofile.html',  picurl=user.picurl, about=about)

@login_required
@main.route('/profile/registerapi')
def registerfreeapi():
    apiuser = API.query.filter_by(owner=current_user.username).first()
    if apiuser:
        return render_template('registerapi.html', text="API key already registred", key=apiuser.key)
    else:
        S = 24   
        newkey = ''.join(random.choices(string.ascii_letters + string.digits, k = S))
        apiuser = API.query.filter_by(key=newkey).first()
        if apiuser:
            registerfreeapi()
        if current_user.username == 'admin':
            tier = "Paid"
        else:
            tier = "Free"
        apiuser = API(key=newkey, owner=current_user.username, tier=tier, rate='{"hour": "00", "no.": "0"}')
        db.session.add(apiuser)
        db.session.commit()
        return render_template('registerapi.html', text="API key registred", key=newkey)


@login_required
@main.route('/profile/settings', methods=['POST'])
def upload_profile_picture_POST():
    if 'file' not in request.files:
        about = request.form.get('about')
        try: 
            about.encode('ascii')
        except UnicodeEncodeError:
            flash('Text is not ascii')
            return redirect(url_for('main.editprofile'))

        if len(about) >= 500:
            flash('About text too long')
            return redirect(url_for('main.editprofile'))

        user = User.query.filter_by(username=current_user.username).first()
        user.about = escape(about)
        db.session.commit()

        return redirect(url_for('main.profile'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('main.editprofile'))
    if file and allowed_file(file.filename):
        file.save('app/static/user-uploads/' + str(current_user.id) + 'profilepic.png')
        flash('Image successfully uploaded')
        return redirect(url_for('main.profile'))

    flash('File must be .png or .jpg')
    return url_for('main.editprofile')

@main.route('/profile/<user>')
def user(user):
    return str(user)
