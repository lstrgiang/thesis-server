import unittest
import json
from flask_api import status
from project.server import db
from project.server.models import  BlacklistToken, User
from project.tests.base import BaseTestCase
from project.tests.helpers import DatabasePrepare, PostHTTP
class TestAuthBlueprint(BaseTestCase):

    def test_registration(self):
        """
        Test the user registration
        """
        with self.client:
            response = PostHTTP.register_success(self.client);
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertTrue(response.content_type=='application/json')
            self.assertEqual(response.status_code,status.HTTP_200_OK)
    def test_registered_with_already_registered_user(self):
        """ Test registration with already registered email"""
        DatabasePrepare.create_new_user()
        with self.client:
            response = PostHTTP.register_success(self.client)
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'fail')
            self.assertTrue(
                data['message'] == 'User already exists. Please Log in.')
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
    def test_registered_user_login(self):
        """ Test for login of registered-user"""
        with self.client:
            # Register new user
            # Login with registered user
            DatabasePrepare.create_new_user()
            response = PostHTTP.login_success(self.client)
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertTrue(data['message'] == 'Successfully logged in.')
            self.assertTrue(data['auth_token'])
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, status.HTTP_200_OK)
    def test_registered_unconfirmed_user_login(self):
        """ Test for login of registered-user but unconfirmed"""
        with self.client:
            DatabasePrepare.create_new_user(False)
            response = PostHTTP.login_success(self.client)
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'fail')
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
    def test_registered_user_login_with_encrypted_key(self):
        """ Test for login function with registered user and encrypted key"""
        with self.client:
            DatabasePrepare.add_new_encrypted_key()
            response = PostHTTP.login_success_with_mac(self.client)
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertTrue(data['message'] == 'Successfully logged in.')
            self.assertTrue(data['auth_token'])
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            modulus, exponent = User.decode_auth_key(data['auth_token'])
    def test_non_registered_user_login(self):
        """ Test for login of non-registered user """
        with self.client:
            response = self.client.post(
                '/auth/login',
                data=json.dumps(dict(
                    email='giangcoi@gmail.com',
                    password='123456'
                )),
                content_type='application/json'
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'fail')
            self.assertTrue(data['message'] == 'User does not exist.')
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
    def test_valid_logout(self):
        """ Test for logout before token expires """
        with self.client:
            # user registration
            DatabasePrepare.create_new_user()
            # user login
            resp_login = PostHTTP.login_success(self.client)
            data_login = json.loads(resp_login.data.decode())
            self.assertTrue(data_login['status'] == 'success')
            self.assertTrue(data_login['message'] == 'Successfully logged in.')
            self.assertTrue(data_login['auth_token'])
            self.assertTrue(resp_login.content_type == 'application/json')
            self.assertEqual(resp_login.status_code, status.HTTP_200_OK)
            # valid token logout
            response = self.client.post(
                '/auth/logout',
                headers=dict(
                    Authorization='Bearer ' + json.loads(
                        resp_login.data.decode()
                    )['auth_token']
                )
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertTrue(data['message'] == 'Successfully logged out.')
            self.assertEqual(response.status_code, status.HTTP_200_OK)
    def test_valid_blacklisted_token_logout(self):
        """ Test for logout after a valid token gets blacklisted """
        with self.client:
            # user registration
            DatabasePrepare.create_new_user()
            # user login
            resp_login = PostHTTP.login_success(self.client)
            data_login = json.loads(resp_login.data.decode())
            # blacklist a valid token
            blacklist_token = BlacklistToken(
                token=data_login['auth_token'])
            db.session.add(blacklist_token)
            db.session.commit()
            # blacklisted valid token logout
            response = PostHTTP.post_with_token(self.client,'/auth/logout',
                resp_login.data.decode())
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'fail')
            self.assertTrue(data['message'] == 'Token is blacklisted. Please login again.')
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    def test_valid_blacklisted_token_user(self):
        """ Test for user status with a blacklisted valid token """
        with self.client:
            DatabasePrepare.create_new_user()
            resp_login = PostHTTP.login_success(self.client)
            data_login = json.loads(resp_login.data.decode())
            # blacklist a valid token
            blacklist_token = BlacklistToken(
                token=data_login['auth_token'])
            db.session.add(blacklist_token)
            db.session.commit()
            response = PostHTTP.post_with_token(self.client,'/auth/status',
                    resp_login.data.decode())
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'fail')
            self.assertTrue(data['message'] == 'Token is blacklisted. Please login again.')
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
if __name__=='__main__':
    unittest.main()
