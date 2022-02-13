from . import db, create_app
from .models import User
from werkzeug.security import generate_password_hash

def create_database():
    db.create_all(app=create_app()) # Create Database