import unittest
from project.tests.base import BaseTestCase
from project.tests.helpers import DatabasePrepare
from project.server.helper import KeyOperation, OTP
from project.server.models import RSAPair
from project.server import app, db
# from project.server.models import RSAPair
# from project.server import db
from Crypto.Cipher import PKCS1_OAEP
class TestEncryption(BaseTestCase):
    def test_re_encryption(self):
        """ Test for Re-encryption operation"""
        server_key = KeyOperation.generate_new_pair()
        client_key = KeyOperation.generate_new_pair()
        pair = RSAPair(str(server_key.n),
            int(server_key.e),str(server_key.d))
        db.session.add(pair)
        db.session.commit()
        key = "This is a test key"
        encrypted_key = KeyOperation.encrypt(server_key.publickey(), key)
        new_key = KeyOperation.re_encryption(server_key,[str(client_key.n),
            str(client_key.e)],encrypted_key)
        self.assertEqual(key, KeyOperation.decrypt(client_key,new_key))

    def test_encrypt_OTP(self):
        """ Test for OTP code generation and encryption """
        device, private_key= DatabasePrepare.add_new_device()
        code = KeyOperation.encrypt_OTP(device)
        rsa_key=PKCS1_OAEP.new(private_key)
        de_code = rsa_key.decrypt(code)
        self.assertTrue(isinstance(code,bytes))
        self.assertTrue(isinstance(de_code,bytes))
        self.assertTrue(OTP.verify(app.config['SECRET_KEY'], int(de_code)))
    def test_generate_key_pair(self):
        """ Test for key pairs generation """
        private_key= KeyOperation.generate_new_pair()
        self.assertTrue(private_key.has_private())
        self.assertTrue(isinstance(private_key.exportKey(),bytes))
    def test_import_public_key(self):
        """ Test for public key import"""
        new_key = KeyOperation.generate_new_pair()
        public_key = KeyOperation.import_key(new_key.publickey().exportKey())
        self.assertFalse(public_key.has_private())
        self.assertEqual(public_key.exportKey(),new_key.publickey().exportKey())

    def test_key_differences(self):
        """Test if the generated keys are different"""
        key1 = KeyOperation.generate_new_pair()
        key2 = KeyOperation.generate_new_pair()
        pub1 = key1.publickey()
        pub2 = key2.publickey()
        self.assertNotEqual(key1.exportKey(), key2.exportKey())
        self.assertNotEqual(pub1.exportKey(), pub2.exportKey())
    def test_invalid_key_import(self):
        """ Test for key import function with invalid key"""
        with self.assertRaises(Exception) as context:
            KeyOperation.import_key("Invalid Key")
        self.assertTrue('RSA key format is not supported' in str(context.exception))

if __name__=='__main__':
    unittest.main()
