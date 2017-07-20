from flask import  request,  json
from project.server import db
from flask.views import MethodView
from flask_api import status
from project.server.models import User,DeviceList
from project.server.helper import CommonResponseObject,  RequestUtils, DatabaseCheck

class KeyAPI(MethodView):
    """
    Register for encryption key
    """
    def get(self):
        auth_header = request.headers.get('Authorization')
        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token= ''
        if auth_token:
            response = User.decode_auth_token(auth_token)
            if not isinstance(response, str):
                user = User.get_user_by_id(response)
                data = json.dumps(dict(encrypted_key=user.encrypted_key))
                return CommonResponseObject.success_response(data)
            return CommonResponseObject.token_response(response)
        else:
            return CommonResponseObject.unauthorized_token_response()
    def __check_for_require_params(self,auth_token,mac_address,
            otp_modulus,otp_exponent,main_key, backup_key):
        """
        Check if the params is qualified
        :params auth_token mac_address public_key:
        :return user_id or responseObject:
        """
        if not auth_token:
            return CommonResponseObject.unauthorized_token_response()
        user_id = User.decode_auth_token(auth_token)
        if not main_key:
            return CommonResponseObject.fail_response(
                    'Please provide the main key',
                    status.HTTP_412_PRECONDITION_FAILED)
        if not backup_key:
            return CommonResponseObject.fail_response(
                    'Please provide the backup_key',
                    status.HTTP_412_PRECONDITION_FAILED)
        if isinstance(user_id,str):
            return CommonResponseObject.unauthorized_token_response()
        if not isinstance(mac_address,str):
            return CommonResponseObject.fail_response(
                'Please provide your Mac address',
                status.HTTP_412_PRECONDITION_FAILED)
        user = User.get_user_by_id(user_id)
        if not user:
            return CommonResponseObject.unauthorized_token_response()
        if DatabaseCheck.is_mac_address_existed(mac_address):
            return CommonResponseObject.fail_response(
                'Your device is the root device or already requested for authorization',
                status.HTTP_202_ACCEPTED)
        return user
    def post(self):
        """
        Add root device
        """
        #Get authentication token
        auth_token = RequestUtils.get_access_token(request)
        #Get post data
        post_data = request.get_json()
        mac_address =post_data.get('mac_address')
        os = post_data.get('os') or "Unknown"
        backup_key = post_data.get('backup_key')
        otp_modulus = post_data.get('otp_modulus')
        otp_exponent = post_data.get('otp_exponent')
        main_key = post_data.get('main_key')
        root = post_data.get('is_root')
        user= self.__check_for_require_params(auth_token,
                mac_address,otp_modulus,otp_exponent, main_key, backup_key)
        if not isinstance(user,User):
            return user
        root_device = DeviceList.get_root_device(user.id)
        if root_device and root:
            return CommonResponseObject.fail_response(
                'The account already register a root device',
                status.HTTP_202_ACCEPTED)
        device = DeviceList(user,
                mac_address=mac_address,
                main_key=main_key,
                backup_key=backup_key,
                otp_modulus=otp_modulus,
                otp_exponent=otp_exponent,
                os=os,
                is_root=root)
        try:
            db.session.add(device)
            db.session.commit()
            modulus, exponent = User.decode_public_key(auth_token)
            auth_token = User.encode_auth_token(user.id,str(modulus),
                    str(exponent),main_key)
            return CommonResponseObject.login_success(auth_token,
                    'You are able to encrypt your file now')
        except Exception as e:
            print(e)
            return CommonResponseObject.fail_response(
                    'Some error occured, please try again.')

