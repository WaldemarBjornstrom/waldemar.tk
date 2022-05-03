from flask import Blueprint, render_template, flash, request, redirect, url_for, abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_required, current_user, fresh_login_required
from .models import User, API
from . import db
import os

def getusersinhtml():
    users = User.query.all()
    html = '<ul>'
    for user in users:
        html = html + '<li><a href="/profile/' + user.username + '">' + str(user.username) + '</a></li><br>'

    return html + '</ul>'

def getalldatabaseinhtml():
    users = User.query.all()
    html =  '''
            <table>
                <tr>
                    <th>User ID</th>
                    <th>Username</th>
                    <th>Password</th>
                    <th>Salt</th>
                    <th>Github_OAUTH</th>
                    <th>Github_ID</th>
                    <th>Name</th>
                    <th>Permission</th>
                    <th>About</th>
                    <th>Picture URL</th>
                    <th>Data 1</th>
                    <th>Data 2</th>
                    <th>Int 1</th>
                    <th>Int 2</th>
                </tr>
            '''
    for user in users:
        html = html + '<tr><td>' + str(user.id) + '</td>' + '<td>' + str(user.username) + '</td>' + '<td>' + str(user.password) + '</td>' + '<td>' + str(user.salt) + '</td>' + '<td>' + str(user.github_oauth) + '</td>' + '<td>' + str(user.github_user_id) + '</td>' + '<td>' + str(user.name) + '</td>' + '<td>' + str(user.permission) + '</td>' + '<td>' + str(user.about) + '</td>' + '<td>' + str(user.picurl) + '<td>' + str(user.data1) + '</td>' + '<td>' + str(user.data2) + '</td>' + '<td>' + str(user.int1) + '</td>' +'<td>' + str(user.int2) + '</td></tr>'
    html = html + '</table>'
    return html

def getallAPIdatabaseinhtml():
    users = API.query.all()
    html =  '''
            <table>
                <tr>
                    <th>Key</th>
                    <th>Owner</th>
                    <th>Tier</th>
                    <th>Rate</th>
                </tr>
            '''
    for user in users:
        html = html + '<tr><td>' + str(user.key) + '</td>' + '<td>' + str(user.owner) + '</td>' + '<td>' + str(user.tier) + '</td><td>' + str(user.rate) + '</td></tr>'
    html = html + '</table>'
    return html

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
    elif view == 'db':
        if not os.environ['ENVIRONMENT'] == 'DEBUG':
            flash('Database viewing disabled')
            return redirect(url_for('admin.admin_page'))
        header = 'Database'
        data = getalldatabaseinhtml() + '<br><br><h2>API Database</h2>' + getallAPIdatabaseinhtml()
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

@admin.route('/admin/editdb')
@fresh_login_required
def editdb():
    if not os.environ['ENVIRONMENT'] == 'DEBUG':
        flash('Database editing disabled')
        return redirect(url_for('admin.admin_page'))
    if not amadmin(current_user.username):
        abort(403)
    return render_template('editdb.html')

@admin.route('/admin/editdb', methods=['POST'])
@fresh_login_required
def editdb_POST():
    if not os.environ['ENVIRONMENT'] == 'DEBUG':
        flash('Database editing disabled')
        return redirect(url_for('admin.admin_page'))
    if not amadmin(current_user.username):
        abort(403)

    edit = request.form.get('edit')
    adminpassword = request.form.get('password')
    user = User.query.filter_by(username='admin').first()
    if not check_password_hash(user.password, adminpassword):
        flash('Invalid admin password')
        return redirect(url_for('admin.editdb'))
    username = request.form.get('username')
    column = request.form.get('column')
    value = request.form.get('value')
    key = request.form.get('key')

    if edit == 'Userdb':
        user = User.query.filter_by(username=username).first()

        if user:
            if column == 'username':
                oldvalue = str(user.username)
                user.username = str(value)
            elif column == 'password':
                oldvalue = str(user.password)
                user.password = generate_password_hash(str(value), method='sha256')
            elif column == 'name':
                oldvalue = str(user.name)
                user.name = str(value)
            elif column == 'permission':
                oldvalue = str(user.permission)
                user.permission = str(value)
            elif column == 'about':
                oldvalue = str(user.about)
                user.about = str(value)
            elif column == 'picurl':
                oldvalue = str(user.picurl)
                user.picurl = str(value)
            else:
                flash('choose a value to change')
            db.session.commit()
            flash('Successfully changed ' + column + ' for ' + user.username + ' from ' + oldvalue + ' to ' + value)
        else:
            flash('User does not exist')
    elif edit == 'APIdb':
        apiuser = API.query.filter_by(key=key).first()
        if apiuser:
            if column == 'owner':
                oldvalue = str(apiuser.owner)
                apiuser.owner = str(value)
            elif column == 'tier':
                oldvalue = str(apiuser.tier)
                apiuser.tier = value
            elif column == 'rate':
                oldvalue = str(apiuser.rate)
                apiuser.rate = value
            else:
                flash('Choose value to change')
            db.session.commit()
            flash('Successfully changed ' + column + ' for ' + apiuser.key + ' from ' + oldvalue + ' to ' + value)
        else:
            flash('User does not exist')
    
    return redirect(url_for('admin.editdb'))