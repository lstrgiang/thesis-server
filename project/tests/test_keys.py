import unittest, json, base64
# import json
# import time
# from flask_api import status
from project.tests.base import BaseTestCase
from project.tests.helpers import DatabasePrepare, PostHTTP
from project.server.helper import KeyOperation
from Crypto.Cipher import AES
class TestKeysInDeviceBluePrint(BaseTestCase):

    """
    Test Devices API
    """
    def __generate_encrypted_keys(self,private_key):
        secret_key='1234567890123456'
        cipher = AES.new(secret_key,AES.MODE_ECB)
        exponent = str(private_key.e)
        exponent+= ((16 - len(exponent) % 16)*'X')
        modulus = str(private_key.n)
        modulus+= ((16 - len(modulus) % 16)*'X')
        encrypted_exponent=base64.b64encode(cipher.encrypt(exponent))
        encrypted_modulus =base64.b64encode(cipher.encrypt(modulus))
        return encrypted_exponent.decode('utf-8'), encrypted_modulus.decode('utf-8')

    def test_valid_register_root_device(self):
        """
        Register root device: Valid test case
        """
        with self.client:
            DatabasePrepare.create_new_user()
            token = PostHTTP.login_success(self.client)
            private_key= KeyOperation.generate_new_pair()
            data = json.dumps(dict(
                mac_address=DatabasePrepare.SUCCESS_MAC_ADDR,
                os=DatabasePrepare.SUCCESS_OS,
                backup_key='backup_key',
                otp_modulus=str(private_key.n),
                otp_exponent=int(private_key.e),
                main_key='main_key'))
            response = PostHTTP.post_with_token(self.client,
                    '/key/root',token.data.decode(),
                    data)
            data = json.loads(response.data.decode())
            self.assertEqual(data['status'],'success')
if __name__ == '__main__':
    unittest.main()
