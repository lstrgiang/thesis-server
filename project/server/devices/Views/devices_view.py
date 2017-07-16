from flask import request, json
from flask.views import MethodView
from project.server import  db
from flask_api import status
from project.server.helper import CommonResponseObject, RequestUtils, KeyOperation, DatabaseCheck, OTP
from project.server.models import User, DeviceList, RSAPair

class DeviceAPI(MethodView):

    """
    APIs to manage devices
    """
    def get(self):
        # Get the access token from the header
        auth_token = RequestUtils.get_access_token(request)
        if auth_token:
            response = User.decode_auth_token(auth_token)
            if not isinstance(response,str):
                device_list = DeviceList.get_device_by_user_id(response)
                data = [device.serialize() for device in device_list]
                return CommonResponseObject.success_response(data)
            return CommonResponseObject.fail_response(response,status.HTTP_401_UNAUTHORIZED)
        else:
            return CommonResponseObject.unauthorized_token_response()
class RequestAuthorizeAPI(MethodView):
    """
    Request for authorization
    """
    def __check_for_require_params(self,auth_token,mac_address,key_mod,key_ex):
        """
        Check if the params is qualified
        :params auth_token mac_address public_key:
        :return user_id or responseObject:
        """
        if not auth_token:#check if auth_token is available
            return CommonResponseObject.unauthorized_token_response()
        #get user_id and key from the auth_token
        user_id, key= User.decode_auth_token_key(auth_token)
        if isinstance(user_id,str):#check if user_id is valid
            return CommonResponseObject.unauthorized_token_response()
        if not isinstance(mac_address,str): #check if mac_address is valid
            return CommonResponseObject.fail_response(
                'Please provide your MAC address',
                status.HTTP_412_PRECONDITION_FAILED)
        #check if key is valid
        if not RSAPair.is_key_exists(key):#check if key is existed
            return CommonResponseObject.response(
                'Some errors occured, provided key does not exists')
        user = User.get_user_by_id(user_id) #retrieve the user entity
        if not user: #check if the user is existed
            return CommonResponseObject.unauthorized_token_response()
        #check if the mac_address is stored
        if DatabaseCheck.is_mac_address_existed(mac_address):
            if DatabaseCheck.is_root_by_mac(mac_address):
                return CommonResponseObject.fail_response(
                    'Your device is the root device',
                    status.HTTP_202_ACCEPTED)
            return CommonResponseObject.fail_response(
                'Your device is already authorized',
                status.HTTP_202_ACCEPTED)
        return user, key
    def __process_new_key(self,user_id, key, key_mod, key_exp):
        """
        Process key passing down to the new authorized device with
        provided key from the root device and encrypt the key with
        provided public key from the device
        """
        device = DeviceList.get_root_device(user_id) #get root device by user_id
        if not device: #if root device does not exist
            return CommonResponseObject.fail_response(
                'Some errors occured, please try again')
        encrypted_key = KeyOperation.re_encryption(key,
            [key_mod,key_exp], device.encrypted_key)
        if not encrypted_key:
            return CommonResponseObject.fail_response(
                'Some errors occured, please try again')
        data = json.dumps(dict(key=encrypted_key))
        return CommonResponseObject.success_response(data)
    def post(self):
        """
        Post Request to verify the OTP code using the non-root device
        and non-authorized devices
        :params:
            :auth_token: authorized token when logged in
            :mac_address: unique MAC address of the device
            :code: OTP code for verification
            :key_mod: modulus of a public key
            :key_exp: exponent of a public key
        :returns:
            :error response: or :encrypted_key:
        """
        try:
            post_data = request.get_json() #Get data from post request body
            auth_token = RequestUtils.get_access_token(request) #Return authentication token
            mac_address = post_data.get('mac_address') #Get mac address from the body
            code = post_data.get('code') #Get authorized code
            key_mod = post_data.get('modulus') #Get public key from the body
            key_ex = post_data.get('exponent') #Check the provided params, return user_id if qualified
            user, key= self.__check_for_require_params(auth_token,mac_address,key_mod,key_ex)
            #If returned result is not an integer
            if not isinstance(user,User):
                return user
            #Return the exception message if it fail
            if OTP.verify(user,code)!=True:
                return CommonResponseObject.fail_response('Invalid code.',
                    status.HTTP_401_UNAUTHORIZED)
            return self.__process_new_key(user.id, key, key_mod, key_ex)
        except Exception:
            return CommonResponseObject.fail_response(
                'Missing important fields or values')
class RequestOTPAPI(MethodView):
    """
    API to provide OTP for authorization
    """
    def __check_for_require_params(self,auth_token,mac_address,encrypted_key):
        """
        Check if the params is qualified, return error json response
        if any requisite does not meet, else check and return user
        entity for the corresponding user id
        :params:
            :auth_token:
            :mac_address:
            :public_key:
        :return:
            :user_id: or :responseObject:
        """
        if not auth_token: # Check if the auth_token is valid
            return CommonResponseObject.unauthorized_token_response()
        user_id = User.decode_auth_token(auth_token)
        if isinstance(user_id,str): # Check if user_id is provided
            return CommonResponseObject.unauthorized_token_response()
        if not isinstance(mac_address,str): # Check if mac address is provided
            return CommonResponseObject.fail_response(
                'Please provide your Mac address',
                status.HTTP_412_PRECONDITION_FAILED)
        if not encrypted_key:#check if encrypted_key is provided
            return CommonResponseObject.fail_response(
                'Please provide your encrypted key for authorization',
                status.HTTP_412_PRECONDITION_FAILED)
        user = User.get_user_by_id(user_id) #get user from the database
        if not user:#if user is not available
            return CommonResponseObject.unauthorized_token_response()
        return user
    def __generate_encrypted_OTP(self, user_id, mac_address,encrypted_key):
        """
        Store the received key in the database associate with the root
        device for later re-encryption with support authorization
        other devices by encrypt the key with other identifier
        :params:
            :user_id: the id of the user
            :mac_address: MAC address of the device
            :encrypted_key: temporarily encrypted key
        :returns:
            :Error Response: or :JSON object contains encrypted_code:
        """
        device = DeviceList.get_root_device(user_id)
        if not device: #Check if root device is stored
            return CommonResponseObject.fail_response(
                'Please register for the root device to process further encryption',
                status.HTTP_401_UNAUTHORIZED)
        if device.mac_address != mac_address: #check if the access mac_address is the root device
            return CommonResponseObject.fail_response(
                'Please request for authorization with your root device',
                status.HTTP_403_FORBIDDEN)
        encrypted_code=  KeyOperation.encrypt_OTP() #generate encrypted code
        return json.dumps(dict(code=encrypted_code)) #jsonize and return
    def post(self):
        """
        Request for retrieving OTP code
        :params:
            :auth_token: authentication token which is given only when logged in
            :mac_address: MAC address of the device
            :encrypted_key: the key A encrypted with provided public key
        :returns:
            :encrypted_code: OTP code encrypted with provided public key
        """
        post_data = request.get_json() # Get json data from post body
        auth_token = RequestUtils.get_access_token(request) #Get token from post header
        mac_address = post_data.get('mac_address') # Get mac address from the post body
        encrypted_key = post_data.get('encrypted_key') # Get encrypted key from the root
        user= self.__check_for_require_params(auth_token, mac_address,
            encrypted_key) # Check if the params satisfy the requirements
        if not isinstance(user,User):
            return user
        return self.__generate_encrypted_OTP(user.id, mac_address, encrypted_key)


