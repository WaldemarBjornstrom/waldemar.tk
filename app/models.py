from flask_login import UserMixin
from . import db

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    permission = db.Column(db.String(20))
    about = db.Column(db.String(1000))
    picurl = db.Column(db.String(500))

class API(db.Model):
    key = db.Column(db.String(100), primary_key=True)
    owner = db.Column(db.String(100))
    tier = db.Column(db.String(100))
    rate = db.Column(db.String(1000))