import datetime
import jwt
from sqlalchemy import and_
from project.server import app, db, bcrypt

class User(db.Model):
    """
    User Model for storing user related details
    """
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key = True, autoincrement = True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    bday = db.Column(db.DateTime(), nullable=False)
    fullname = db.Column(db.String(255), nullable=False)
    job = db.Column(db.String(255), nullable=True)
    country = db.Column(db.String(255), nullable=True)
    registered_on = db.Column(db.DateTime, nullable=False)
    device_list = db.relationship('DeviceList', backref='user',lazy='dynamic')
    def __init__(self, email, password, bday, fullname,
            job=None, country=None):
        self.email = email
        self.password = bcrypt.generate_password_hash(
                password, app.config.get('BCRYPT_LOG_ROUNDS')
        ).decode()
        self.registered_on = datetime.datetime.now()
        self.bday=bday
        self.fullname=fullname
        self.country=country
        self.job=job
    @staticmethod
    def get_user_by_email(user_email):
        return User.query.filter_by(email=user_email).first()
    @staticmethod
    def get_user_by_id(user_id):
        return User.query.filter_by(id=user_id).first()

    @staticmethod
    def encode_auth_token(user_id, modulus=None, exponent=None, main_key=None):
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
                'modulus': modulus if modulus else "No modulus is available",
                'exponent': exponent if exponent else "No exponent is available",
                'key': main_key if main_key else "No main key is available"
            }
            return jwt.encode(
                    payload,
                    app.config.get('SECRET_KEY'),

            )
        except Exception as e:
            return e
    def decode_auth_token_key(auth_token):
        try:
            payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'))
            is_blacklisted_token = BlacklistToken.check_blacklist(auth_token)
            if is_blacklisted_token:
                return 'Token is blacklisted. Please login again.'
            else:
                return payload['sub'], [payload['modulus'], payload['exponent']]
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please login again.'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please login again.'
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
    @staticmethod
    def decode_auth_key(auth_token):
        try:
            payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'))
            return payload['modulus'], payload['exponent']
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
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    registered_on = db.Column(db.DateTime, nullable=False)
    mac_address = db.Column(db.String(17), nullable=False)
    os = db.Column(db.String(255), nullable=False)
    is_root = db.Column(db.String(255), nullable=False)
    main_key = db.Column(db.String(255), nullable=False)
    backup_key = db.Column(db.String(255), nullable=False)
    otp_modulus = db.Column(db.String(500), nullable=False)
    otp_exponent = db.Column(db.Integer, nullable=False)
    encrypted_key = db.Column(db.String(255), nullable=True)

    def serialize(self):
        return {
            'id': self.id,
            'mac_address': self.mac_address,
            'os': self.os,
            'registered_on': self.registered_on
        }
    def __init__(self, user, mac_address, os,backup_key,
            main_key, otp_modulus, otp_exponent,is_root=False):
        self.user = user
        self.backup_key =backup_key
        self.registered_on = datetime.datetime.now()
        self.main_key = main_key
        self.otp_modulus=otp_modulus
        self.otp_exponent=otp_exponent
        self.mac_address=mac_address
        self.os = os
        self.is_root=is_root
        self.encrypted_key = None

    @staticmethod
    def get_root_device(user_id):
        return DeviceList.query.filter(and_(DeviceList.user.has(id=user_id),DeviceList.is_root is True)).first()
    @staticmethod
    def get_device_by_user_id_and_mac(user_id,mac):
        return DeviceList.query.filter(and_(DeviceList.user.has(id=user_id),DeviceList.mac_address==mac)).first()
    @staticmethod
    def get_device_by_mac(mac):
        return DeviceList.query.filter_by(mac_address=mac).first()
    @staticmethod
    def get_device_by_user_id(user_id):
        return DeviceList.query.filter(DeviceList.user.has(id=user_id))
    @staticmethod
    def is_root(mac):
        return DeviceList.get_device_by_mac(mac).is_root
class RSAPair(db.Model):
    """
    RSAPair model for database mapping to create RSAPair table
    which store RSA Key Pairs generated for each of login session
    """
    __tablename__= 'rsa_key'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    public_modulus= db.Column(db.String(), nullable=False)
    public_exponent= db.Column(db.Integer, nullable=False)
    public_exponent= db.Column(db.String(), nullable=False)

    def __init__(self,public_modulus, public_exponent, private_exponent):
        """
        RSAPair Model Constructor
        :params:
            :modulus: public modulus
            :exponent: public exponent
            :key_mod: private modulus
        :returns: void
        """
        self.public_modulus = public_modulus
        self.public_exponent = public_exponent
        self.private_exponent= private_exponent

    @staticmethod
    def is_existed(key):
        """
        Check if provided key is existed
        :params: :key: list or RSA instance of the key
        :returns: True or False
        """
        if isinstance(key,list):
            rsa_key = RSAPair.query.filter_by(public_modulus=key[0]).first()
            print(rsa_key)
        else:
            rsa_key = RSAPair.query.filter_by(public_modulus=str(key.n)).first()
        return True if rsa_key else False
    @staticmethod
    def get_RSA_by_public(public_key):
        """
        Get stored RSAPair from the public key
        :params: :public_key: the corresponding public key
        :returns: :RSAPair:
        """
        if isinstance(public_key, list):
            return RSAPair.query.filter_by(public_modulus=public_key[0]).first()
        else:
            return RSAPair.query.filter_by(public_modulus=str(public_key.n)).first()

class BlacklistToken(db.Model):
    """
    Token Model for storing JWT tokens
    """
    __tablename__ = 'blacklist_tokens'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    token = db.Column(db.String(1024), unique=True, nullable=False)
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
