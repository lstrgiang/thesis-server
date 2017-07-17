from flask import  make_response, jsonify, copy_current_request_context
from flask_api import status
from project.server import app
from flask_mail import Message
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA
from Crypto.Cipher import PKCS1_v1_5
from project.server import db, mail
from project.server.models import DeviceList, User, RSAPair
from itsdangerous import URLSafeTimedSerializer
import pyotp,base64, hashlib, os, ast, threading
class ConfirmationToken:
    @staticmethod
    def generate_confirmation_token(email):
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

    @staticmethod
    def confirm_token(token, expiration=3600):
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        try:
            email = serializer.loads(
                token,
                salt=app.config['SECURITY_PASSWORD_SALT'],
                max_age=expiration
            )
        except:
            return False
        return email
class Mail:
    @staticmethod
    def send(receiver, subject, template):
        mess = Message(subject, recipients=[receiver],
                html=template,sender = app.config['MAIL_DEFAULT_SENDER'])
        Mail.send_async(mess)
    @staticmethod
    def send_async(mess):
        @copy_current_request_context
        def send_message(mess):
            mail.send(mess)
        sender = threading.Thread(name='mail_sender', target=send_message, args=(mess,))
        sender.start()

class OTP:
    @staticmethod
    def get_new_code(secret=app.config['SECRET_KEY']):
        return pyotp.TOTP(base64.b32encode(secret.encode('ascii'))).now()
    @staticmethod
    def verify(code,secret=app.config['SECRET_KEY']):
        """
        valid_window = 2 by default (2*30s = 60s = 1mins)
        """
        totp = pyotp.TOTP(base64.b32encode(secret.encode('ascii')))
        return totp.verify(code,valid_window=5)
    # need to store new encrypted key as new device and generate
    # backup key that is sent back to the user email


class DatabaseCheck:
    @staticmethod
    def is_root_by_mac(mac_address):
        """
        Check if the MAC address is belong to a root device
        :params:
            :mac_address: MAC address that need to be checked
        :returns:
            True if it is the root device else False
        """
        device_list = DeviceList.get_device_by_mac(mac_address)
        if device_list and device_list.root:
            return True
        return False
    @staticmethod
    def is_mac_address_existed(mac_address):
        """
        Check if the MAC address is existed in the database
        :params: :mac_address: MAC address that need to be checked
        :returns: True or False
        """
        device_list = DeviceList.get_device_by_mac(mac_address)
        if device_list :
            return True
        return False
    @staticmethod
    def remove_key_pair(auth_token):
        modulus, exponent= User.decode_public_key(auth_token)
        key = RSAPair.get_RSA_by_public(modulus)
        if not key:
            return
        db.session.delete(key)
        db.session.commit()

    @staticmethod
    def prepare_auth_token(user_id,mac_address,main_key=None):
        """
        Prepare params for generating authentication token
        :params:
            :user_id: the unique id of the user
            :mac_address: MAC address of the device
            :main_key: (None) main encrypted key
        :returns: auth_token
        """
        while True:
            private_key = KeyOperation.generate_new_pair()
            if not RSAPair.is_existed(private_key):
                break
        auth_token = User.encode_auth_token(user_id,
            str(private_key.n),str(private_key.e),main_key)
        DatabaseCheck.store_new_key_pairs(private_key)
        return auth_token
    @staticmethod
    def store_new_key_pairs(private_key):
        key = RSAPair(str(private_key.n), int(private_key.e),
            str(private_key.d))
        db.session.add(key)
        db.session.commit()


class RequestUtils:
    @staticmethod
    def get_access_token(request):
        auth_header=request.headers.get('Authorization')
        if auth_header:
            return auth_header.split(" ")[1]
        return False
class CommonResponseObject:
    @staticmethod
    def response(responseObject, code):
        return make_response(jsonify(responseObject)), code
    @staticmethod
    def success_response(data, success_code=status.HTTP_200_OK):
        """
        Return success response
        """
        responseObject={
            'status': 'success',
            'data': data
        }
        return make_response(jsonify(responseObject)), success_code
    @staticmethod
    def success_resp_with_mess(message, success_code=status.HTTP_200_OK):
        """
        Return success response with message
        """
        responseObject = {
            'status':'success',
            'message': message
        }
        return make_response(jsonify(responseObject)), success_code
    @staticmethod
    def fail_response(message, error_code=status.HTTP_500_INTERNAL_SERVER_ERROR):
        responseObject={
            'status':'fail',
            'message':message
        }
        return make_response(jsonify(responseObject)),error_code

    @staticmethod
    def unauthorized_token_response():
        return CommonResponseObject.fail_response(
            message='Provide a valid auth token.',
            error_code=status.HTTP_401_UNAUTHORIZED)

    @staticmethod
    def forbiden_token_response():
        return CommonResponseObject.fail_response(
            message='Provide a valid auth token.',
            error_code=status.HTTP_403_FORBIDDEN)

    @staticmethod
    def register_success(auth_token):
        responseObject = {
            'status': 'success',
            'message': 'Successfully registered.',
            'auth_token': auth_token.decode()
        }
        return make_response(jsonify(responseObject)), status.HTTP_201_CREATED

    @staticmethod
    def register_exception():
        return CommonResponseObject.fail_response(
            message='Some error occurred. Please try again.',
            error_code=status.HTTP_401_UNAUTHORIZED)

    @staticmethod
    def register_user_exist():
        return CommonResponseObject.fail_response(
            message='User already exists. Please Log in.',
            error_code=status.HTTP_202_ACCEPTED)
    @staticmethod
    def login_success(auth_token, mess=None):
        if mess is None:
            mess= 'Successfully logged in.'
        responseObject = {
            'status': 'success',
            'message': mess,
            'auth_token': auth_token.decode()
        }
        return make_response(jsonify(responseObject)), status.HTTP_200_OK
    @staticmethod
    def login_user_not_exist():
        return CommonResponseObject.fail_response(
            message='User does not exist.',
            error_code=status.HTTP_404_NOT_FOUND)

    @staticmethod
    def login_exception():
        return CommonResponseObject.fail_response(
            message='Try again',
            error_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @staticmethod
    def logout_success():
        return CommonResponseObject.success_resp_with_mess(
                'Successfully logged out.')
    @staticmethod
    def logout_exception(e):
        return CommonResponseObject.fail_response(e)
    @staticmethod
    def token_response(resp):
        return CommonResponseObject.fail_response(
            message=resp,
            error_code=status.HTTP_401_UNAUTHORIZED)
class KeyOperation:
    @staticmethod
    def re_encryption(key, client_key, encrypted_key):
        """
        Perform decryption with server_key and encryption with client_key
        to return the encrypted_key to client
        :params:
            :server_key: RSAPair object of the server key combination
            :client_key: list of modulus and exponent of client provided key
            :encrypted_key: provided key by the root device
        :returns: :new_encrypted_key:
        """
        server_private = RSA.construct([int(key.public_modulus), int(key.public_exponent),
            int(key.private_exponent)])
        raw = KeyOperation.decrypt(server_private,encrypted_key)
        return KeyOperation.simple_encrypt(client_key[0], client_key[1],raw)
    @staticmethod
    def simple_encrypt(modulus, exponent, raw):
        modulus = int(modulus)
        encrypted = ""
        for char in list(raw):
            encrypted+=str(pow(ord(char),exponent,modulus))+":"
        return encrypted[:-1]

    @staticmethod
    def simple_decrypt(exponent, modulus, encrypted):
        decrypted = ""
        for char in encrypted.split(':'):
            decrypted+=chr(pow(char,exponent,modulus))
        return decrypted
    @staticmethod
    def encrypt(public_key, raw):
        """
        Perform encryption with provided public_key and raw data
        :params:
            :public_key: RSA public key object
            :raw: raw data to be encrypted
        :returns: :encrypted_data:
        """
        public_cipher = PKCS1_OAEP.new(public_key)
        if isinstance(raw,str):
            return public_cipher.encrypt(raw.encode())
        else:
            return public_cipher.encrypt(raw)
    @staticmethod
    def decrypt(private_key, encrypted):
        """
        Perform decryption with provided private_key and encrypted data
        :params:
            :private_key: RSA private key object
            :encrypted: encrypted data
        :returns: :raw: raw data
        """
        dsize = SHA.digest_size
        sentinel = Random.new().read(15+dsize)
        cipher = PKCS1_v1_5.new(private_key)
        print(private_key.n)
        return cipher.decrypt(base64.b64decode(encrypted),sentinel).decode()

    @staticmethod
    def convert_to_32(data):
        """
        Convert data to 32base data
        :params: :data:
        :returns: :32base data:
        """
        return data + (32 - len(data) % 32) * chr(32 - len(data) % 32)
    @staticmethod
    def aes_random_encrypt(raw):
        """
        Encrypt the raw bit with AES and randomly generated key
        """
        key = os.urandom(128)[:15]
        return KeyOperation.aes_encrypt(raw,key), key
    @staticmethod
    def aes_encrypt(raw, key):
        """
        Encrypt the raw bit with AES and provided key
        :params:
            :raw: raw list of bit or string
            :key: key of encryption
        :returns: :encrypted_raw:
        """
        raw = KeyOperation.convert_to_32(raw) #Convert raw to 32based raw
        key = hashlib.sha256(key.encode()).digest() #hash the key with SHA256
        iv = Random.new().read(AES.block_size) #Generate randomly iv key
        cipher = AES.new(key, AES.MODE_CBC, iv) #Create cipher from key
        return base64.b64encode(iv + cipher.encrypt(raw)) #Encrypt the key
    @staticmethod
    def aes_decrypt(encrypted , key):
        """
        Decrypt the encrypted with AES and key
        :params:
            :encrypted: data need to be decrypted
            :key: encryption key
        :returns: :raw:
        """
        encrypted = base64.b64decode(encrypted) #convert to byte
        iv = encrypted[:AES.block_size] #generate iv from the encrypted
        cipher = AES.new(key, AES.MODE_CBC, iv) #Create cipher from key
        return KeyOperation.convert_to_32(( #decryption
            cipher.decrypt(encrypted[AES.block_size:])).decode('utf-8'))

    @staticmethod
    def encrypt_OTP(device):
        """
        Generate an OTP code and encrypt it with public key associated
        with provided device
        :params:
            :device: device entity of the root device
        :returns:
            :encrypted_key: encrypted OTP code
        """
        otp_modulus = device.otp_modulus #get the modulus of the public key
        otp_exponent = device.otp_exponent #get the exponent of the public key
        code= OTP.get_new_code(app.config['SECRET_KEY'])
        encrypted_key = pow(int(code),int(otp_exponent),int(otp_modulus))
        return encrypted_key #return the key

    @staticmethod
    def generate_new_pair():
        """
        Generate RSA Key pair with default exponent = 65547
        """
        return RSA.generate(1024)
    @staticmethod
    def construct_key(modulus, exponent, private_exponent = None):
        """
        Construct a key from provided modulus and exponent, give
        a private modulus to generate the private key object
        :params:
            :modulus: public modulus of the key
            :exponent: public exponent of the key
            :private_exponent: private modulus of the private key
        :return: RSA Key object
        """
        if private_exponent:
            return RSA.construct([modulus,exponent,private_exponent])
        return RSA.construct([modulus,exponent])
    @staticmethod
    def import_key(public_key):
        return RSA.importKey(public_key)
    @staticmethod
    def is_valid(public_key):
        """
        Check if a public_key is valid
        :params:
            :public_key: the list or public key object
        :returns: True or False or exception message
        """
        if isinstance(public_key,list): #if the parameter is a list
            try: #try to construct the key
                RSA.construct(public_key)
                return True
            except Exception as e:
                return e
        else: #if the parameter is a RSA Key object
            try:
                RSA.importKey(public_key) #import that key directly
                return True
            except Exception as e:
                return e
    @staticmethod
    def authorize_new_device(user, mac_address, key):
        private_key = RSA.construct([key.key_mod,key.key_ex])
        return private_key

