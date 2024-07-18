from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
import os

class Config:

    app = Flask(__name__)
    app.secret_key = 'hasanyigit61'

    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:hasanyigit61@localhost/lynx'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db = SQLAlchemy(app)
    migrate = Migrate(app, db)
    login_manager = LoginManager(app)
    login_manager.login_view = 'login'

    UPLOAD_FOLDER = 'static/images'

    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hasanyigit61'
    MAIL_SERVER = 'smtp.your-email-provider.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'lynxgamingmanagement@gmail.com'
    MAIL_PASSWORD = 'omdyqrtmvvinmhav'
    MAIL_DEFAULT_SENDER = 'lynxgamingmanagement@gmail.com'
