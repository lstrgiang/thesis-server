import unittest, json
# import json
# import time
# from flask_api import status
from project.tests.base import BaseTestCase
from project.tests.helpers import DatabasePrepare, GetHTTP, PostHTTP
from project.server.helper import KeyOperation, OTP
from project.server.models import User

class TestDevicesBlueprint(BaseTestCase):
    """
    Test Devices API
    """
    def test_OTP(self):
        """ Test for generating OTP code"""
        DatabasePrepare.create_new_user()
        user = User.query.first()
        auth_token = User.encode_auth_token(user.id)
        self.assertTrue(isinstance(auth_token,bytes))
#     def test_valid_request_authorize(self):
        # with self.client:
            # DatabasePrepare.create_new_user()
            # token = PostHTTP.login_success(self.client)
            # public_key = KeyOperation.generate_new_pair().publickey()
            # data = json.dumps(dict(
                # mac_address=DatabasePrepare.SECOND_MAC_ADDR,
                # modulus=int(public_key.n),
                # exponent=int(public_key.e)))
            # response = PostHTTP.post_with_token(self.client,
                    # '/devices/request-authorize',token.data.decode(),
                    # data)
            # data = json.loads(response.data.decode())
            # self.assertEqual(data['status'],'success')
    # def test_valid_get_devices(self):
        # with self.client:
            # DatabasePrepare.add_new_device()
            # token = PostHTTP.login_success(self.client)
            # response = GetHTTP.get_with_token(self.client,'/devices',token.data.decode())
            # data = json.loads(response.data.decode())
            # self.assertTrue(data['status'] == 'success')
# def test_valid_post_encrypted_key(self):
        # with self.client:
            # resp_register = PostHTTP.register_success(self.client)
            # json_data = json.dumps(dict(encrypted_key='example_token'))
            # response = PostHTTP.post_with_token(self.client,'/auth/key',
                    # resp_register.data.decode(),
                    # json_data)
            # data = json.loads(response.data.decode())
            # self.assertTrue(data['status'] == 'success')
            # self.assertEqual(response.status_code, status.HTTP_200_OK)
            # response = GetHTTP.get_with_token(self.client,'/auth/key',
                    # resp_register.data.decode())
            # data = json.loads(response.data.decode())
            # self.assertTrue(data['status'] == 'success')
            # self.assertEqual(data['data']['encrypted_key'],'example_token')
            # self.assertEqual(response.status_code, status.HTTP_200_OK)
    # def test_post_existed_encrypted_key(self):
        # with self.client:
            # resp_register = PostHTTP.register_success(self.client)
            # json_data = json.dumps(dict(encrypted_key='example_token'))
            # response = PostHTTP.post_with_token(self.client,'/auth/key',
                    # resp_register.data.decode(),
                    # json_data)
            # json_data = json.dumps(dict(encrypted_key='change_token'))
            # response = PostHTTP.post_with_token(self.client,'/auth/key',
                    # resp_register.data.decode(),
                    # json_data)
            # data = json.loads(response.data.decode())
            # self.assertEqual(data['status'], 'fail')
# def test_valid_get_empty_encrypted_key(self):
        # with self.client:
            # resp_register = PostHTTP.register_success(self.client)
            # response = GetHTTP.get_with_token(self.client,'/auth/key',
                   # resp_register.data.decode())
            # data = json.loads(response.data.decode())
            # self.assertTrue(data['status'] == 'success')
            # self.assertEqual(response.status_code, status.HTTP_200_OK)

if __name__=='__main__':
    unittest.main()
