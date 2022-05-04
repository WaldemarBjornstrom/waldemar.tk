from errors import *
from colors import *
from werkzeug.security import generate_password_hash
import sqlite3, argparse, inquirer, random, string, os, shutil, re

def generate_salt():
    letters = string.ascii_letters + string.digits + string.punctuation
    salt = ''.join(random.choice(letters) for i in range(10))
    return salt

parser = argparse.ArgumentParser(description='Example', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('-O', '--overwrite', action='store_true', help='Overwrite existing database')
parser.add_argument('-d', '--database', default='app/db/db.sqlite', help='Database file')
parser.add_argument('-t', '--table', default='user', help='Table to edit')
parser.add_argument('-D', '--docker', action='store_true', help='Set docker mode')
parser.add_argument('-p', '--password', default='', help='Admin password')
parser.add_argument('action', choices=['useradd', 'userrm', 'edit', 'reset', 'create', 'prepare'], help='Database operation')
parser.add_argument('username', nargs='*', default="none", help='Username(s) for useradd, userrm, edit')
args = parser.parse_args()
config = vars(args)
#print(config)

if config['action'] == 'create' or config['action'] == 'reset' or config['action'] == 'prepare':
    if config['username'] != "none":
        raise InvalidArgumentError("No username allowed for create or reset")
else:
    if config['username'] == "none":
        raise InvalidArgumentError("No username given")

if config['overwrite'] == True or config['action'] == 'reset':
    if os.path.exists(config['database']):
        os.remove(config['database'])

if config['action'] == 'prepare':
    if os.path.exists(config['database']):
        raise InvalidArgumentError("Database already exists")
else:
    if config['password'] != "":
        raise InvalidArgumentError("No password allowed for create or reset")

if os.path.exists(config['database']):
    if config['action'] == 'create':
        raise DBerror("Database already exists")
    db = sqlite3.connect(config['database'])
    cursor = db.cursor()
elif config['action'] == 'create' or config['action'] == 'reset' or config['overwrite'] == True:
    db = sqlite3.connect(config['database'])
    cursor = db.cursor()
    cursor.execute("create table user (id integer primary key, username text, password text, salt text, github_oauth text, github_user_id integer, name text, permission text, about text, picurl text, data1 text, data2 text, int1 integer, int2 integer)")
    cursor.execute("create table API (id integer primary key, key text, owner text, tier text, rate text)")
else:
    raise DBerror("Database not found")

if config['action'] == 'useradd':
    if len(config['username']) > 1:
        raise InvalidArgumentError("Only one username allowed for useradd")
    if len(config['username']) == 0:
        raise InvalidArgumentError("No username given")
    if len(config['username'][0]) > 100:
        raise InvalidArgumentError("Username too long")
    cursor.execute("SELECT * FROM user ORDER BY id DESC LIMIT 1;")
    last_id = cursor.fetchone()
    #print(type(last_id))
    if last_id == None:
        last_id = 0
    else:
        last_id = last_id[0]
        #print(last_id)
    uid = last_id + 1
    cursor.execute("SELECT * FROM user WHERE username=?", (config['username'][0],))
    result = cursor.fetchone()
    if result != None:
        raise UserError("User already exists")
    questions = [
        inquirer.Text('password', message="Password"),
        inquirer.Text('Name', message="Name"),
        inquirer.List('Permission', message="Permission", choices=['Administrator', 'User'], default='user'),
    ]
    answers = inquirer.prompt(questions)
    print(answers)
    salt = generate_salt()
    shutil.copyfile('app/static/user-uploads/default.jpg', 'app/static/user-uploads/' + str(uid) + 'profilepic.png')
    picurl = '/static/user-uploads/' + str(uid) + 'profilepic.png'
    try:
        print("INSERT INTO user (id, username, password, salt, name, permission, picurl) VALUES ('{}', '{}', '{}', '{}', '{}', '{}', '{}')".format(uid, config['username'][0], generate_password_hash(salt + answers['password'], method='sha256'), salt, answers['Name'], answers['Permission'], picurl))
        #cursor.execute("INSERT INTO user (id, username, password, salt, name, permission, picurl) VALUES ({}, {}, {}, {}, {}, {}, {})".format(uid, config['username'][0], generate_password_hash(salt + answers['password'], method='sha256'), salt, answers['Name'], answers['Permission'], picurl))
        cursor.execute("INSERT INTO user (id, username, password, salt, name, permission, picurl) VALUES (?, ?, ?, ?, ?, ?, ?)", (uid, config['username'][0], generate_password_hash(salt + answers['password'], method='sha256'), salt, answers['Name'], answers['Permission'], picurl))
        print(cursor.fetchall())
        db.commit()
    except:
        raise DBerror("Error adding user")
elif config['action'] == 'userrm':
    if len(config['username']) > 1:
        raise InvalidArgumentError("Only one username allowed for userrm")
    if len(config['username']) == 0:
        raise InvalidArgumentError("No username given")
    cursor.execute("SELECT * FROM user WHERE username=?", (config['username'][0],))
    result = cursor.fetchone()
    if result == None:
        raise UserError("User does not exist")
    cursor.execute("DELETE FROM user WHERE username=?", (config['username'][0],))
    db.commit()
elif config['action'] == 'edit':
    if len(config['username']) > 1:
        raise InvalidArgumentError("Only one username allowed for edit")
    if len(config['username']) == 0:
        raise InvalidArgumentError("No username given")
    cursor.execute("SELECT * FROM user WHERE username=?", (config['username'][0],))
    result = cursor.fetchone()
    if result == None:
        raise UserError("User does not exist")
    questions = [
        inquirer.List('edit', message="Edit", choices=['id', 'username','password', 'salt', 'github_oauth', 'github_user_id', 'name', 'permission', 'about', 'picurl', 'data1', 'data2', 'int1', 'int2']),
    ]
    answers = inquirer.prompt(questions)
    if answers['edit'] == 'id':
        print(color.yellow + 'id editing strictly inadvisable. Type exit to exit.' + color.end)
        question = [inquirer.Text('data', message="new id")]
    elif answers['edit'] == 'username':
        question = [inquirer.Text('data', message="new username")]
    elif answers['edit'] == 'password':
        question = [inquirer.Text('data', message="new password")]
    elif answers['edit'] == 'salt':
        question = [inquirer.Text('data', message="new salt")]
    elif answers['edit'] == 'github_oauth':
        print(color.yellow + 'github_oauth editing strictly inadvisable. Type exit to exit.' + color.end)
        question = [inquirer.Text('data', message="new github_oauth")]
    elif answers['edit'] == 'github_user_id':
        print(color.yellow + 'github_user_id editing strictly inadvisable. Type exit to exit.' + color.end)
        question = [inquirer.Text('data', message="new github_user_id")]
    elif answers['edit'] == 'name':
        question = [inquirer.Text('data', message="new name")]
    elif answers['edit'] == 'permission':
        question = [inquirer.List('data', message="new permission", choices=['Administrator', 'User'], default='user')]
    elif answers['edit'] == 'about':
        question = [inquirer.Text('data', message="new about")]
    elif answers['edit'] == 'picurl':
        question = [inquirer.Text('data', message="new picurl")]
    elif answers['edit'] == 'data1':
        question = [inquirer.Text('data', message="new data1")]
    elif answers['edit'] == 'data2':
        question = [inquirer.Text('data', message="new data2")]
    elif answers['edit'] == 'int1':
        question = [inquirer.Text('data', message="new int1")]
    elif answers['edit'] == 'int2':
        question = [inquirer.Text('data', message="new int2")]
    dataanswers = inquirer.prompt(question)

    if answers['edit'] == 'id' or answers['edit'] == 'github_oauth' or answers['edit'] == 'github_user_id':
        question = [inquirer.Confirm('confirm', message="Are you sure you want to edit " + answers['edit'] + "? This is strictly inadvisable.", default=False)]
        confirmanswers = inquirer.prompt(question)
        if confirmanswers['confirm'] != True:
            raise RuntimeError("Aborted")
    question = [inquirer.Confirm('confirm', message="Are you sure you want to change " + answers['edit'] + " to: " + dataanswers['data'], default=False)]
    confirmanswers = inquirer.prompt(question)
    if confirmanswers['confirm'] != True:
        raise RuntimeError("Aborted")
    cursor.execute('UPDATE user SET {}= ? WHERE username=?'.format(answers['edit']), (dataanswers["data"], config["username"][0],))
    db.commit()
elif config['action'] == 'prepare':
    cursor.execute("SELECT * FROM user ORDER BY id DESC LIMIT 1;")
    last_id = cursor.fetchone()
    if last_id == None:
        last_id = 0
    else:
        last_id = last_id[0]
    uid = last_id + 1
    if config['password'] == "":
        print('Asking for password')
        questions = [
            inquirer.Text('password', message="Password"),
        ]
        print('Username is: admin')
        answers = inquirer.prompt(questions)
        password = answers['password']
    else:
        print('password set')
        password = config['password']

    print(password)
    salt = generate_salt()
    shutil.copyfile('app/static/user-uploads/default.jpg', 'app/static/user-uploads/' + str(uid) + 'profilepic.png')
    picurl = '/static/user-uploads/' + str(uid) + 'profilepic.png'
    cursor.execute("INSERT INTO user (id, username, password, salt, name, permission, picurl) VALUES (?, ?, ?, ?, ?, ?, ?)", (uid, 'admin', generate_password_hash(salt + password, method='sha256'), salt, 'Administrator', 'Administrator', picurl))
    last_id = last_id + 1
    uid = last_id + 1
    letters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(letters) for i in range(20))
    salt = generate_salt()
    shutil.copyfile('app/static/user-uploads/default.jpg', 'app/static/user-uploads/' + str(uid) + 'profilepic.png')
    picurl = '/static/user-uploads/' + str(uid) + 'profilepic.png'
    cursor.execute("INSERT INTO user (id, username, password, salt, name, permission, picurl) VALUES (?, ?, ?, ?, ?, ?, ?)", (uid, 'pubapi', generate_password_hash(salt + password, method='sha256'), salt, 'Public API', 'User', picurl))
    cursor.execute("SELECT * FROM API ORDER BY id DESC LIMIT 1;")
    last_id = cursor.fetchone()
    if last_id == None:
        last_id = 0
    else:
        last_id = last_id[0]
    uid = last_id + 1
    S = 24
    key = ''.join(random.choices(string.ascii_letters + string.digits, k = S))
    cursor.execute("INSERT INTO API (id, key, owner, tier, rate) VALUES (?, ?, ?, ?, ?)", (uid, key, 'pubapi', 'Paid', '{"hour": "00", "no.": "0"}'))
    db.commit()