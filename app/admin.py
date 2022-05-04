from flask import Blueprint, render_template, flash, request, redirect, url_for, abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_required, current_user, fresh_login_required
from .models import User, API
from . import db

def getusersinhtml():
    users = User.query.all()
    html = '<ul>'
    for user in users:
        html = html + '<li><a href="/profile/' + user.username + '">' + str(user.username) + '</a></li><br>'

    return html + '</ul>'

def amadmin(username):
    user = User.query.filter_by(username=username).first()
    if user.permission == 'Administrator': return True
    else: return False

admin = Blueprint('admin', __name__)

@admin.route('/admin')
@login_required
def admin_page():
    if not amadmin(current_user.username):
        abort(403)
    return render_template('admin.html')

@admin.route('/admin/current')
@login_required
def current():
    if not amadmin(current_user.username):
        abort(403)
    view = request.args.get('view', default = 'none', type = str)
    if view == 'users':
        header = 'Current users:'
        data = getusersinhtml()
    elif view == 'none':
        header = 'No view selected'
        data = ''
    return render_template('current.html', header=header, data=data)

@admin.route('/admin/permission')
@fresh_login_required
def changeuserpermission():
    if not amadmin(current_user.username):
        abort(403)
    content =   '''
    <br><br>
    <div class="formcontainer">
        <form class="form" method="post">
            <label for="username">Username:</label><br>
            <input type="text" id="username" name="username"><br>
            <select id="permission" name="permission">
                <option value="User">User</value>
                <option value="Administrator">Administrator</value>
            </select><br>
            <input type="submit" value="Change">
        </form>
    </div>
                '''
    return render_template('base.html', content=content)

@admin.route('/admin/permission', methods=['POST'])
@fresh_login_required
def changeuserpermission_POST():
    if not amadmin(current_user.username):
        abort(403)
    username = request.form.get('username')
    permission = request.form.get('permission')

    user = User.query.filter_by(username=username).first()

    if user:
        user.permission = permission
        db.session.commit()
        flash('Successfully changed user pemission for ' + username + ' to ' + permission)
    else:
        flash('User does not exist')
    
    return redirect(url_for('admin.changeuserpermission'))