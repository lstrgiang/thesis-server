import unittest
import json
# import time
from flask_api import status
from project.server import db
from project.server.models import User, BlacklistToken
from project.tests.base import BaseTestCase

class TestAuthBlueprint(BaseTestCase):
    def testing_json_data(self):
        return json.dumps(dict(
            email='giang@gmail.com',
            password='123456'
        ))
    def header_token(self,token):
        """
        Generate header with token
        """
        return dict(Authorization='Bearer '+json.loads(token)['auth_token'])
    def get_with_token(self,url,token,json_data=None):
        """
        GET request with authorized token
        """
        return self.client.get(url,
            data=json_data,
            headers=self.header_token(token))
    def post_with_token(self,url,token,json_data=None):
        """
        POST with authorized token
        """
        return self.client.post(url,
            headers=self.header_token(token),
            data=json_data,
            content_type='application/json'
        )
    def post_without_token(self,url,json_data=None):
        return self.client.post(url,
            data=json_data,
            content_type='application/json'
        )
    def get_without_token(self,url,json_data=None):
        return self.client.post(url,
            data=json_data,
            content_type='application/json'
        )
    def login_success(self):
        return self.post_without_token('/auth/login',
            self.testing_json_data())

    def register_success(self):
        """
        Perform user registration before testing
        """
        return self.post_without_token('/auth/register',
            self.testing_json_data())
    def test_registration(self):
        """
        Test the user registration
        """
        with self.client:
            response = self.register_success();
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertTrue(data['message']=='Successfully registered.')
            self.assertTrue(data['auth_token'])
            self.assertTrue(response.content_type=='application/json')
            self.assertEqual(response.status_code,status.HTTP_201_CREATED)
    def test_registered_with_already_registered_user(self):
        """ Test registration with already registered email"""
        user = User(
            email='giang@gmail.com',
            password='test'
        )
        db.session.add(user)
        db.session.commit()
        with self.client:
            response = self.register_success()
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'fail')
            self.assertTrue(
                data['message'] == 'User already exists. Please Log in.')
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
    def test_registered_user_login(self):
        """ Test for login of registered-user login """
        with self.client:
            # Register new user
            resp_register = self.register_success()
            data_register = json.loads(resp_register.data.decode())
            self.assertTrue(data_register['status'] == 'success')
            self.assertTrue(
                data_register['message'] == 'Successfully registered.'
            )
            self.assertTrue(data_register['auth_token'])
            self.assertTrue(resp_register.content_type == 'application/json')
            self.assertEqual(resp_register.status_code, status.HTTP_201_CREATED)
            # Login with registered user
            response = self.login_success()
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertTrue(data['message'] == 'Successfully logged in.')
            self.assertTrue(data['auth_token'])
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, status.HTTP_200_OK)
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
    def test_user_status(self):
        """ Test for user status """
        with self.client:
            resp_register = self.client.post(
                '/auth/register',
                data=json.dumps(dict(
                    email='giang@gmail.com',
                    password='123456'
                )),
                content_type='application/json'
            )
            response = self.client.get(
                '/auth/status',
                headers=dict(
                    Authorization='Bearer ' + json.loads(
                        resp_register.data.decode()
                    )['auth_token']
                )
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertTrue(data['data'] is not None)
            self.assertTrue(data['data']['email'] == 'giang@gmail.com')
            self.assertTrue(data['data']['admin'] is 'true' or 'false')
            self.assertEqual(response.status_code, status.HTTP_200_OK)
    def test_valid_logout(self):
        """ Test for logout before token expires """
        with self.client:
            # user registration
            resp_register = self.client.post(
                '/auth/register',
                data=json.dumps(dict(
                    email='giang@gmail.com',
                    password='123456'
                )),
                content_type='application/json',
            )
            data_register = json.loads(resp_register.data.decode())
            self.assertTrue(data_register['status'] == 'success')
            self.assertTrue(
                data_register['message'] == 'Successfully registered.')
            self.assertTrue(data_register['auth_token'])
            self.assertTrue(resp_register.content_type == 'application/json')
            self.assertEqual(resp_register.status_code, status.HTTP_201_CREATED)
            # user login
            resp_login = self.client.post(
                '/auth/login',
                data=json.dumps(dict(
                    email='giang@gmail.com',
                    password='123456'
                )),
                content_type='application/json'
            )
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
    # def test_invalid_logout(self):
        # """ Testing logout after the token expires """
        # with self.client:
            # # user registration
            # resp_register = self.register_success()
            # data_register = json.loads(resp_register.data.decode())
            # self.assertTrue(data_register['status'] == 'success')
            # self.assertTrue(
                # data_register['message'] == 'Successfully registered.')
            # self.assertTrue(data_register['auth_token'])
            # self.assertTrue(resp_register.content_type == 'application/json')
            # self.assertEqual(resp_register.status_code, status.HTTP_201_CREATED)
            # # user login
            # resp_login = self.login_success()
            # data_login = json.loads(resp_login.data.decode())
            # self.assertTrue(data_login['status'] == 'success')
            # self.assertTrue(data_login['message'] == 'Successfully logged in.')
            # self.assertTrue(data_login['auth_token'])
            # self.assertTrue(resp_login.content_type == 'application/json')
            # self.assertEqual(resp_login.status_code, status.HTTP_200_OK)
            # # invalid token logout
            # time.sleep(6)
            # response = self.client.post(
                # '/auth/logout',
                # headers=dict(
                    # Authorization='Bearer ' + json.loads(
                        # resp_login.data.decode()
                    # )['auth_token']
                # )
            # )
            # data = json.loads(response.data.decode())
            # self.assertTrue(data['status'] == 'fail')
            # self.assertTrue(
                # data['message'] == 'Signature expired. Please login again.')
            # self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    def test_valid_blacklisted_token_logout(self):
        """ Test for logout after a valid token gets blacklisted """
        with self.client:
            # user registration
            resp_register = self.register_success()
            data_register = json.loads(resp_register.data.decode())
            self.assertTrue(data_register['status'] == 'success')
            self.assertTrue(
                data_register['message'] == 'Successfully registered.')
            self.assertTrue(data_register['auth_token'])
            self.assertTrue(resp_register.content_type == 'application/json')
            self.assertEqual(resp_register.status_code, status.HTTP_201_CREATED)
            # user login
            resp_login = self.login_success()
            data_login = json.loads(resp_login.data.decode())
            self.assertTrue(data_login['status'] == 'success')
            self.assertTrue(data_login['message'] == 'Successfully logged in.')
            self.assertTrue(data_login['auth_token'])
            self.assertTrue(resp_login.content_type == 'application/json')
            self.assertEqual(resp_login.status_code, status.HTTP_200_OK)
            # blacklist a valid token
            blacklist_token = BlacklistToken(
                token=json.loads(resp_login.data.decode())['auth_token'])
            db.session.add(blacklist_token)
            db.session.commit()
            # blacklisted valid token logout
            response = self.post_with_token('/auth/logout',
                resp_login.data.decode())
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'fail')
            self.assertTrue(data['message'] == 'Token is blacklisted. Please login again.')
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    def test_valid_blacklisted_token_user(self):
        """ Test for user status with a blacklisted valid token """
        with self.client:
            resp_register = self.register_success()
            # blacklist a valid token
            blacklist_token = BlacklistToken(
                token=json.loads(resp_register.data.decode())['auth_token'])
            db.session.add(blacklist_token)
            db.session.commit()
            response = self.get_with_token('/auth/status',
                    resp_register.data.decode())
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'fail')
            self.assertTrue(data['message'] == 'Token is blacklisted. Please login again.')
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    def test_valid_get_empty_encrypted_key(self):
        with self.client:
            resp_register = self.register_success()
            response = self.get_with_token('/auth/key',
                   resp_register.data.decode())
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertFalse(data['data']['encrypted_key'])
            self.assertEqual(response.status_code, status.HTTP_200_OK)
    def test_valid_post_encrypted_key(self):
        with self.client:
            resp_register = self.register_success()
            print(resp_register.data)
            json_data = json.dumps(dict(encrypted_key='example_token'))
            response = self.post_with_token('/auth/key',
                    resp_register.data.decode(),
                    json_data)
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            response = self.get_with_token('/auth/key',
                    resp_register.data.decode())
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertEqual(data['data']['encrypted_key'],'example_token')
            self.assertEqual(response.status_code, status.HTTP_200_OK)
    def test_post_existed_encrypted_key(self):
        with self.client:
            resp_register = self.register_success()
            json_data = json.dumps(dict(encrypted_key='example_token'))
            response = self.post_with_token('/auth/key',
                    resp_register.data.decode(),
                    json_data)
            json_data = json.dumps(dict(encrypted_key='change_token'))
            response = self.post_with_token('/auth/key',
                    resp_register.data.decode(),
                    json_data)
            data = json.loads(response.data.decode())
            self.assertEqual(data['status'], 'fail')
if __name__=='__main__':
    unittest.main()
