# tests/helpers.py
import json,datetime
from project.server import db
from project.server.models import User, DeviceList
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
    def register_success(client):
        """
        Perform user registration before testing
        """
        return PostHTTP.post_without_token(client,'/auth/register',
            DatabasePrepare.testing_json_data())

class DatabasePrepare:
    @staticmethod
    def testing_json_data():
        return json.dumps(dict(
            email='giang@gmail.com',
            password='123456',
            country='vietnam',
            job='software engineer',
            fullname='giangle',
            birthday='22/02/1995'

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
                email='giang@gmail.com',
                password='123456',
                bday=datetime.datetime(2017,2,22),
                fullname='le su truong giang'
        )
    @staticmethod
    def create_new_user():
        user = DatabasePrepare.sample_user()
        db.session.add(user)
        db.session.commit()
        return user
    @staticmethod
    def add_new_device():
        user = DatabasePrepare.create_new_user()
        user = User.query.filter_by(email=user.email).first()
        device = DeviceList(
                user,
                mac_address="00:15:E9:2B:99:3C",
                os="macOS Sierra")
        db.session.add(device)
        db.session.commit()
        return device
