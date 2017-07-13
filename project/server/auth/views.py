from flask import Blueprint, request
from flask.views import MethodView
from flask_api import status
from project.server import bcrypt, db
from project.server.models import User, BlacklistToken, DeviceList
from project.server.helper import CommonResponseObject, RequestUtils,DatabaseCheck
import datetime
auth_blueprint = Blueprint('auth', __name__)


class RegisterAPI(MethodView):
    """
    User Registration Resource
    """
    def __check_register_json_data(self,post_data):#Check for json data
        try:
            email = post_data.get('email')
            password = post_data.get('password')
            bday = post_data.get('birthday')
            post_data.get('job')
            fullname=post_data.get('fullname')
            post_data.get('country')
            if not email or not password or not bday or not fullname:
                return CommonResponseObject.fail_response(
                    'Missing email, password, birthday or fullname')
        except Exception:
            return CommonResponseObject.fail_response(
                'JSON data missing required fields')

    def post(self):
        # get the post data
        post_data = request.get_json()
        if post_data is None:
            return CommonResponseObject.fail_response(
                'Please provide required data',status.HTTP_505_PERMISSION_DENIED)
        self.__check_register_json_data(post_data)
        # check if user already exists
        user = User.get_user_by_email(post_data.get('email'))
        if user:
                # return response to inform that user already existed
            return CommonResponseObject.register_user_exist()
        # if user does not exist, try to create new user and store to the database
            # initialize new user object with information from the request
        try:
            user = User(
                email=post_data.get('email'),
                password=post_data.get('password'),
                bday=datetime.datetime.strptime(post_data.get('birthday'),"%d/%m/%Y"),
                job=post_data.get('job'),
                fullname=post_data.get('fullname'),
                country=post_data.get('country')
            )
            # insert the user
            db.session.add(user)
            db.session.commit()
            # generate the auth token
            auth_token = User.encode_auth_token(user.id)
            # return response with auth token
            return CommonResponseObject.register_success(auth_token)
        except Exception as e:
            # database exception, cannot store user information
            print(e)
            return CommonResponseObject.register_exception()
class LoginAPI(MethodView):
    """
    User Login Resource
    """
    def post(self):
        # get the post data
        post_data = request.get_json()
        if post_data is None:
            return CommonResponseObject.fail_response(
                'Please provide required data',status.HTTP_505_PERMISSION_DENIED)
        try:
            # fetch the user data
            user = User.get_user_by_email(post_data.get('email'))
            mac= post_data.get('mac_address')
            if user and bcrypt.check_password_hash(user.password, post_data.get('password')):
                device = DeviceList.get_device_by_user_id_and_mac(user.id,mac)
                auth_token = DatabaseCheck.prepare_auth_token(user.id, mac ,
                        None if not device else device.encrypted_key)
                if auth_token:
                    return CommonResponseObject.login_success(auth_token)
            else:
                return CommonResponseObject.login_user_not_exist()
        except Exception as e:
            print(e)
            return CommonResponseObject.login_exception()
            # define the API resources
class LogoutAPI(MethodView):
    """
    Logout Resource
    """
    def post(self):
        # get auth token
        auth_token = RequestUtils.get_access_token(request)
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                # mark the token as blacklisted
                blacklist_token = BlacklistToken(token=auth_token)
                try:
                    # insert the token
                    db.session.add(blacklist_token)
                    db.session.commit()
                    return CommonResponseObject.logout_success()
                except Exception as e:
                    return CommonResponseObject.logout_exception(e)
            else:
                return CommonResponseObject.token_response(resp)
        else:
            return CommonResponseObject.forbiden_token_response()
class TokenStatusAPI(MethodView):

    def post(self):
        auth_token = RequestUtils.get_access_token(request)
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp,str):
                return CommonResponseObject.success_resp_with_mess(
                        'Token is still available')
            return CommonResponseObject.fail_response(
                    message=resp,error_code=status.HTTP_401_UNAUTHORIZED)
def BackupKeyAPI(MethodView):
    """
    Manage backup key for backing up the authorization key
    """
    def get(self):
        # TODO: implement the retrieval of backup key mechanism
        return None
    def post(self):
        # TODO: implement the storing backup key mechanism
        return None

registration_view = RegisterAPI.as_view('register_api')
login_view = LoginAPI.as_view('login_api')
logout_view = LogoutAPI.as_view('logout_api')
status_view = TokenStatusAPI.as_view('status_api')
# key_view = EncryptedKeyAPI.as_view('key_api')

# add Rules for API Endpoints
auth_blueprint.add_url_rule(
    '/auth/register',
    view_func=registration_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/login',
    view_func=login_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/logout',
    view_func=logout_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/status',
    view_func=status_view,
    methods=['POST']
)
