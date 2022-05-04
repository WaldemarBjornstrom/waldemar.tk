from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_github import GitHub
import os
from dotenv import load_dotenv
import requests

# init SQLAlchemy so we can use it later in our models
db = SQLAlchemy()
# Load environment variables from .env file
if not os.environ.get('docker') == 'true':
    load_dotenv()

def create_app():
    global github
    app = Flask(__name__)
    UPLOAD_FOLDER = 'static/user-uploads/'

    app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
    
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
    
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.config['GITHUB_CLIENT_ID'] = os.environ['GITHUB_CLIENT_ID']
    app.config['GITHUB_CLIENT_SECRET'] = os.environ['GITHUB_CLIENT_SECRET']
    github = GitHub(app)

    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    from .models import User
    from .models import API

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from .admin import admin as admin_blueprint
    app.register_blueprint(admin_blueprint)

    from .api import api as api_blueprint
    app.register_blueprint(api_blueprint, url_prefix='/api')

    return app