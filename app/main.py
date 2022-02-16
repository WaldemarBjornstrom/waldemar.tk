from flask import Blueprint, render_template, flash, request, redirect, url_for, send_from_directory, escape, abort
from werkzeug.utils import secure_filename
from flask_login import login_required, current_user

from app.admin import current
from . import db
from .models import User

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
    return render_template('projects.html')

@main.route('/profile')
@login_required
def profile():
    username = current_user.username
    user = User.query.filter_by(username=username).first()
    usermenu = '<ul>'
    if current_user.permission == 'Administrator':
        usermenu = usermenu + '<li><a href="' + url_for('admin.admin_page') + '">Admin area</a></li><br>'
    usermenu = usermenu + '<li><a href="' + url_for('main.editprofile') + '">Edit profile</a></li><br></ul>'

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
    print('About text is: ' + about)
    return render_template('editprofile.html',  picurl=user.picurl, about=about)

@login_required
@main.route('/profile/settings', methods=['POST'])
def upload_profile_picture_POST():
    if 'file' not in request.files:
        print('No file. Updating about me text')
        about = request.form.get('about')
        print('About text is: ' +  about)
        try: 
            print('Testing ascii')
            about.encode('ascii')
        except UnicodeEncodeError:
            print('text not ascii')
            flash('Text is not ascii')
            return url_for('main.editprofile')

        if len(about) >= 500:
            print('text too long')
            flash('About text too long')
            return url_for('main.editprofile')
        
        print('finding user in db')
        user = User.query.filter_by(username=current_user.username).first()
        print('user is: ' + str(user))
        user.about = escape(about)
        db.session.commit()
        print('Commited changes to db')

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
