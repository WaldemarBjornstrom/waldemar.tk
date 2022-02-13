from flask import Blueprint, render_template, flash, request, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename
from flask_login import login_required, current_user
from . import allowed_file
import os

main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/projects')
def projects():
    return render_template('projects.html')

@main.route('/profile')
@login_required
def profile():
    return render_template('profile.html', picurl=url_for('static', filename='user-uploads/' + str(current_user.id) + 'profilepic.png'))

@main.route('/profile/upload')
def upload_profile_picture():
    return render_template('uploadprofilepic.html',  picurl=url_for('static', filename='user-uploads/' + str(current_user.id) + 'profilepic.png'))

@main.route('/profile/upload', methods=['POST'])
def upload_profile_picture_POST():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(url_for('main.index'))
    file = request.files['file']

    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('main.upload_profile_picture'))
    if file and allowed_file(file.filename):
        file.save('app/static/user-uploads/' + str(current_user.id) + 'profilepic.png')
        flash('Image successfully uploaded')
        return redirect(url_for('main.profile'))

    flash('File must be .png or .jpg')
    return url_for('main.upload_profile_picture')
