# tests/helpers.py
import json,datetime
from project.server import db
from project.server.models import User, DeviceList
from project.server.helper import KeyOperation
class GetHTTP:
    @staticmethod
    def get_with_token(client,url,token,json_data=None):
        """
        GET request with authorized token
        """
        return client.get(url,
            data=json_data,
            headers=DatabasePrepare.header_token(token))
    @staticmethod
    def get_without_token(client,url,json_data=None):
        return client.post(url,
            data=json_data,
            content_type='application/json'
        )
class PostHTTP:
    @staticmethod
    def post_with_token(client,url,token,json_data=None):
        """
        POST with authorized token
        """
        return client.post(url,
            headers=DatabasePrepare.header_token(token),
            data=json_data,
            content_type='application/json'
        )
    @staticmethod
    def post_without_token(client,url,json_data=None):
        return client.post(url,
            data=json_data,
            content_type='application/json'
        )

    @staticmethod
    def login_success(client):
        return PostHTTP.post_without_token(client,'/auth/login',
            DatabasePrepare.testing_json_data())
    @staticmethod
    def login_success_with_mac(client):
        return PostHTTP.post_without_token(client,'/auth/login',
            DatabasePrepare.testing_json_data_with_mac())
    @staticmethod
    def register_success(client):
        """
        Perform user registration before testing
        """
        return PostHTTP.post_without_token(client,'/auth/register',
            DatabasePrepare.testing_json_data())

class DatabasePrepare:
    SUCCESS_EMAIL = 'giang@gmail.com'
    SUCCESS_PASS = '123456'
    SUCCESS_COUNTRY = 'vietnam'
    SUCCESS_JOB = 'software engineer'
    SUCCESS_FULLNAME = 'giangle'
    SUCCESS_BIRTHDAY = '22/2/1995'
    SUCCESS_MAC_ADDR= '00:15:E9:2B:99:3C'
    SECOND_MAC_ADDR = '00:15:E9:2B:99:4C'
    SUCCESS_OS='macOS Sierra'
    SUCCESS_ENCRYPTED_KEY = "Testing Encrypted Key"
    @staticmethod
    def testing_json_data():
        return json.dumps(dict(
            email=DatabasePrepare.SUCCESS_EMAIL,
            password=DatabasePrepare.SUCCESS_PASS,
            country=DatabasePrepare.SUCCESS_COUNTRY,
            job=DatabasePrepare.SUCCESS_JOB,
            fullname=DatabasePrepare.SUCCESS_FULLNAME,
            birthday=DatabasePrepare.SUCCESS_BIRTHDAY

        ))
    @staticmethod
    def testing_json_data_with_mac():
        return json.dumps(dict(
            email=DatabasePrepare.SUCCESS_EMAIL,
            password=DatabasePrepare.SUCCESS_PASS,
            country=DatabasePrepare.SUCCESS_COUNTRY,
            job=DatabasePrepare.SUCCESS_JOB,
            fullname=DatabasePrepare.SUCCESS_FULLNAME,
            birthday=DatabasePrepare.SUCCESS_BIRTHDAY,
            mac_address=DatabasePrepare.SUCCESS_MAC_ADDR
        ))
    @staticmethod
    def header_token(token):
        """
        Generate header with token
        """
        return dict(Authorization='Bearer '+json.loads(token)['auth_token'])


    @staticmethod
    def sample_user():
        return User(
                email=DatabasePrepare.SUCCESS_EMAIL,
                password=DatabasePrepare.SUCCESS_PASS,
                bday=datetime.datetime.strptime(DatabasePrepare.SUCCESS_BIRTHDAY,
                    '%d/%m/%Y'),
                fullname=DatabasePrepare.SUCCESS_FULLNAME
        )
    @staticmethod
    def create_new_user():
        user = DatabasePrepare.sample_user()
        db.session.add(user)
        db.session.commit()
        return user
    @staticmethod
    def add_new_encrypted_key():
        user = DatabasePrepare.create_new_user()
        user = User.query.filter_by(email=user.email).first()
        public_key=KeyOperation.generate_new_pair().publickey()
        device = DeviceList(
                user,
                mac_address=DatabasePrepare.SUCCESS_MAC_ADDR,
                os=DatabasePrepare.SUCCESS_OS,
                backup_key='asdfasdf',
                main_key='main key',
                otp_modulus=int(public_key.n),
                otp_exponent=int(public_key.e),
                is_root=True)
        db.session.add(device)
        db.session.commit()
        return device
    @staticmethod
    def add_new_device(public_key=None):
        user = DatabasePrepare.create_new_user()
        user = User.query.filter_by(email=user.email).first()
        private_key=KeyOperation.generate_new_pair()
        public_key=private_key.publickey()
        device = DeviceList(
                user,
                mac_address=DatabasePrepare.SUCCESS_MAC_ADDR,
                os=DatabasePrepare.SUCCESS_OS,
                main_key='main key',
                backup_key='asdfasdf',
                otp_modulus=int(public_key.n),
                otp_exponent=int(public_key.e),
                is_root=True)
        db.session.add(device)
        db.session.commit()
        return device, private_key
