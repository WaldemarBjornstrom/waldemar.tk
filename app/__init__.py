from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from os.path import exists
import requests

# init SQLAlchemy so we can use it later in our models
db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    UPLOAD_FOLDER = 'static/user-uploads/'

    app.config['SECRET_KEY'] = 'Super_Secret_Key_sshhhh!'
    if exists('localdev') or exists('docker'):
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db/db.sqlite'
    else:
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///home/pxadmin/db.sqlite'
    
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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