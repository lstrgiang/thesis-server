# project/server/config.py

import os
basedir = os.path.abspath(os.path.dirname(__file__))
postgres_local_base = 'postgresql://postgres:@localhost/'
database_name = 'thesis_jwt_auth'


class BaseConfig:
    """Base configuration."""
    SECRET_KEY = 'my_precious'
    DEBUG = False
    BCRYPT_LOG_ROUNDS = 13
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.getenv('SECRET_KEY', 'my_precious')
    SECURITY_PASSWORD_SALT = os.getenv('SECRET_KEY_SALT','my_precious_two')
    MAIL_SERVER = 'smtp.googlemail.com'
    MAIL_PORT = 465
    MAIL_USE_TLS = False
    MAIL_USE_SSL = True

    MAIL_USERNAME = os.getenv('APP_MAIL_USERNAME','scloud.service.mail@gmail.com')
    MAIL_PASSWORD = os.getenv('APP_MAIL_PASSWORD','thesis2017')

    # mail accounts
    MAIL_DEFAULT_SENDER = 'scloud.service.mail@gmail.com'


class DevelopmentConfig(BaseConfig):
    """Development configuration."""
    DEBUG = True
    BCRYPT_LOG_ROUNDS = 4
    SQLALCHEMY_DATABASE_URI = postgres_local_base + database_name
class TestingConfig(BaseConfig):
    """Testing configuration."""
    DEBUG = True
    TESTING = True
    BCRYPT_LOG_ROUNDS = 4
    SQLALCHEMY_DATABASE_URI = postgres_local_base + database_name + '_test'
    PRESERVE_CONTEXT_ON_EXCEPTION = False

class ProductionConfig(BaseConfig):
    """Production configuration."""
    SECRET_KEY = 'my_precious'
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = postgres_local_base + database_name
    # SQLALCHEMY_DATABASE_URI = os.environ['DATABASE_URL']

