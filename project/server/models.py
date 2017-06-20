import datetime
import jwt
from project.server import app, db, bcrypt

class User(db.Model):
    """
    User Model for storing user related details
    """
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key = True, autoincrement = True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    bday = db.Column(db.DateTime(), nullable=False)
    fullname = db.Column(db.String(255), nullable=False)
    job = db.Column(db.String(255), nullable=True)
    country = db.Column(db.String(255), nullable=True)
    registered_on = db.Column(db.DateTime, nullable=False)
    device_list = db.relationship('DeviceList', backref='user',lazy='dynamic')

    def __init__(self, email, password, bday, fullname, job=None, country=None):
        self.email = email
        self.password = bcrypt.generate_password_hash(
                password, app.config.get('BCRYPT_LOG_ROUNDS')
        ).decode()
        self.registered_on = datetime.datetime.now()
        self.bday=bday
        self.fullname=fullname
        self.country=country
        self.job=job

    def encode_auth_token(self, user_id, key = None):
        """
        Generates the Auth Token
        :param user_id key:
        :return: string
        """
        try:
            payload = {
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1),
                'iat': datetime.datetime.utcnow(),
                'sub': user_id,
                'key': key if key else "No key is available"
            }
            return jwt.encode(
                    payload,
                    app.config.get('SECRET_KEY'),
                    algorithm='HS256'
            )
        except Exception as e:
            return e
    @staticmethod
    def decode_auth_token(auth_token):
        """
        Decodes the authentication token
        :param auth_token:
        :return: integer|string
        """
        try:
            payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'))
            is_blacklisted_token = BlacklistToken.check_blacklist(auth_token)
            if is_blacklisted_token:
                return 'Token is blacklisted. Please login again.'
            else:
                return payload['sub']
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please login again.'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please login again.'
class DeviceList(db.Model):
    """
    Model for storing list of devices associate with a user
    """
    __tablename__='device_list'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    mac_address = db.Column(db.String(255), nullable=False)
    os = db.Column(db.String(255), nullable=False)
    is_root = db.Column(db.String(255), nullable=False)
    backup_key = db.Column(db.String(255), nullable=True)
    encrypted_key= db.Column(db.String(255), nullable=True)

    def serialize(self):
        return {
            'id': self.id,
            'mac_address': self.mac_address,
            'os': self.os,
        }
    def __init__(self, user, mac_address, os, is_root=False):
        self.user = user
        self.backup_key = None
        self.encrypted_key = None
        self.mac_address=mac_address
        self.os = os
        self.is_root=is_root


class BlacklistToken(db.Model):
    """
    Token Model for storing JWT tokens
    """
    __tablename__ = 'blacklist_tokens'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    token = db.Column(db.String(500), unique=True, nullable=False)
    blacklisted_on = db.Column(db.DateTime, nullable=False)

    def __init__(self, token):
        self.token = token
        self.blacklisted_on = datetime.datetime.now()

    def __repr__(self):
        return '<id: token: {}'.format(self.token)
    @staticmethod
    def check_blacklist(auth_token):
        result = BlacklistToken.query.filter_by(token=str(auth_token)).first()
        return True if result else False
