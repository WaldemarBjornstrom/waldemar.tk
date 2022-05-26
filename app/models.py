from flask_login import UserMixin
from . import db

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
    username = db.Column(db.String(100), unique=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    salt = db.Column(db.String(500))
    github_oauth = db.Column(db.String(500))
    github_user_id = db.Column(db.Integer)
    name = db.Column(db.String(100))
    permission = db.Column(db.String(20))
    about = db.Column(db.String(1000))
    picurl = db.Column(db.String(500))
    data1 = db.Column(db.String(1000))
    data2 = db.Column(db.String(1000))
    int1 = db.Column(db.Integer)
    int2 = db.Column(db.Integer)

class API(db.Model):
    key = db.Column(db.String(100), primary_key=True)
    owner = db.Column(db.String(100))
    tier = db.Column(db.String(100))
    rate = db.Column(db.String(1000))

class QueryUser(object):
    @staticmethod
    def by_username(username):
        return User.query.filter_by(username=username).first()

    @staticmethod
    def by_id(id):
        return User.query.get(id)

    @staticmethod
    def by_email(email):
        return User.query.filter_by(email=email).first()

    @staticmethod
    def by_username_or_email(username_or_email):
        return User.query.filter(db.or_(User.username == username_or_email, User.email == username_or_email)).first()
