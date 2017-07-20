import unittest
from project.tests.base import BaseTestCase
from project.tests.helpers import DatabasePrepare
from Crypto.PublicKey import RSA
from project.server.helper import KeyOperation, OTP
from project.server.models import RSAPair
from project.server import app, db
# from project.server.models import RSAPair
# from project.server import db
from Crypto.Cipher import PKCS1_OAEP
class TestEncryption(BaseTestCase):
    def test_reencryption(self):
        encrypted = "aN21B3h43kOLKWuOiGT60I5vfcsKlYH3zYIooM+J2pibn6hP7jLt1iIV8hcrhPy6oqGjwHxIa80hZOi6Ft+14Z1Cx1obQg41EQXKumEdtdMQQRU83E/5BlSj5FazlPL0hw5Eq9jHPD0jjKQKGyweffR1KoutdKw9eckvgsdVzmE="
        modulus = "41152522433320028391414260781121497823282123701983808635098754820396967694895340897354177567517177955359187927090779247132253"
        exponent = 65537
        client_key = [modulus, exponent]
        private_modulus = "142726703398204652638983205261056701155333711876208792179823725379405391177226233307493985630102928083443969675569314017341101313742878761646666945060512448216012474295251166957446341076584025136192653321034456686250636705163190125533995791546789620904080575419998483165635991043375407234471039627424868630751"
        private_exponent = "72318318503199443065485379207225077059755047839743432899208179328835845779058417831788955564319818314340355845043718976667316955696168195645221313832254086569715579154289054303717394893568550659258684584880193477360716438016938382963649944129554410505344022913436211714770421462926877446557028989632059973473"
        server_key = RSAPair(private_modulus, exponent, private_exponent)
        new_encrypted = KeyOperation.re_encryption(server_key,client_key,encrypted)
        print(new_encrypted)



    # def test_encrypt_OTP(self):
        # """ Test for OTP code generation and encryption """
        # device, private_key= DatabasePrepare.add_new_device()
        # code = KeyOperation.encrypt_OTP(device)
        # rsa_key=PKCS1_OAEP.new(private_key)
        # de_code = rsa_key.decrypt(code)
        # self.assertTrue(isinstance(code,bytes))
        # self.assertTrue(isinstance(de_code,bytes))
        # self.assertTrue(OTP.verify(app.config['SECRET_KEY'], int(de_code)))
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
