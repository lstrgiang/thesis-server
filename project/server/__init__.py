# project/server/__init__.py

import os

from flask import Flask
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

app_settings = os.getenv(
    'APP_SETTINGS',
    'project.server.config.ProductionConfig'
)
app.config.from_object(app_settings)

bcrypt = Bcrypt(app)
db = SQLAlchemy(app)

# Register auth blueprint for implementing auth API
from project.server.auth.views import auth_blueprint
app.register_blueprint(auth_blueprint)

# Register device blueprint for implementing devices API
from project.server.devices.views import devices_blueprint
app.register_blueprint(devices_blueprint)


