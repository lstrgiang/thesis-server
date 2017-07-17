from flask import Blueprint, request,  url_for
from flask.views import MethodView
from flask_api import status
from project.server import bcrypt, db
from project.server.models import User, BlacklistToken, DeviceList
from project.server.helper import CommonResponseObject, RequestUtils
from project.server.helper import ConfirmationToken
from project.server.helper import DatabaseCheck, Mail
import datetime
auth_blueprint = Blueprint('auth', __name__)

class ProfileAPI(MethodView):
    """
    User Information updating API
    """
    def get(self):
        """
        User Information retrieval API
        """
        auth_token =  RequestUtils.get_access_token(request)
        user_id = User.decode_auth_token(auth_token)
        user = User.query.filter_by(id=user_id).first()
        if not user:
            return CommonResponseObject.fail_response(
                'User does not exist, please try again',
                status.HTTP_404_NOT_FOUND)
        responseObject={
            'status': 'success',
            'birthday': user.birthday,
            'fullname': user.fullname,
            'job': user.job,
            'country': user.country
        }
        return CommonResponseObject.response(responseObject,
            status.HTTP_200_OK)

    def post(self):
        post_data= request.json()
        if post_data is None:
            return CommonResponseObject.fail_response(
                'Please provde required data', status.HTTP_403_FORBIDDEN)
        auth_token = RequestUtils.get_access_token(request) #Return authentication token
        user_id = User.decode_auth_token(auth_token)
        user = User.query.filter_by(id=user_id).first()
        if not user:
            return CommonResponseObject.fail_response(
                'User does not exist, please try again',
                status.HTTP_404_NOT_FOUND)
        isChanged= False
        password = post_data.get('password')
        if password:
            user.password = password
            isChanged=True
        bday = post_data.get('birthday')
        if bday:
            isChanged = True
            user.birthday =  datetime.datetime.strptime(bday,"%d/%m/%Y")
        job = post_data.get('job')
        if job:
            user.job = job
            isChanged = True
        fullname=post_data.get('fullname')
        if fullname:
            user.fullname = fullname
            isChanged = True
        country = post_data.get('country')
        if country:
            user.country = country
            isChanged = True
        if isChanged:
            db.session.save()
            db.session.commit()
        return CommonResponseObject.success_resp_with_mess(
            'Your information is updated successfully')
class RegisterAPI(MethodView):
    """
    User Registration Resource
    """
    def __check_register_json_data(self,post_data):#Check for json data
        email = post_data.get('email')
        password = post_data.get('password')
        bday = post_data.get('birthday')
        job = post_data.get('job')
        fullname=post_data.get('fullname')
        country = post_data.get('country')
        if not email or not password or not fullname:
            return CommonResponseObject.fail_response(
                'Missing email, password, birthday or fullname')
        user = User(
            email=email,
            password=password,
            bday=datetime.datetime.strptime(bday,"%d/%m/%Y"),
            job=job,
            fullname=fullname,
            country=country
        )
        return user

    def post(self):
        # get the post data
        post_data = request.get_json()
        if post_data is None:
            return CommonResponseObject.fail_response(
                'Please provide required data',status.HTTP_403_FORBIDDEN)
        user = User.get_user_by_email(post_data.get('email'))
        if user:
                # return response to inform that user already existed
            return CommonResponseObject.register_user_exist()
        # if user does not exist, try to create new user and store to the database
            # initialize new user object with information from the request
        try:
            user = self.__check_register_json_data(post_data)
            if not isinstance(user,User):
                return user
            # insert the user
            db.session.add(user)
            db.session.commit()
            token = ConfirmationToken.generate_confirmation_token(user.email)
            confirm_url = url_for('auth.confirm_api', token=token, _external=True)
            html = "<p>Welcome! Thanks for signing up. Please follow this link to activate your account:</p><p><a href="+confirm_url+">{{ Activate}}</a></p><br><p>Cheers!</p>"
            subject = "Scloud Service Email Confirmation"
            Mail.send(user.email, subject, html)
            # generate the auth token
            # return response with auth token
            return CommonResponseObject.success_resp_with_mess(
                'Register succesfully, please confirm your email which is sent to your email address')
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
                'Please provide required data',status.HTTP_404_NOT_FOUND)
        try:
            # fetch the user data
            user = User.get_user_by_email(post_data.get('email'))
            if user and not user.is_confirmed:
                return CommonResponseObject.fail_response(
                'Please confirm your email address which is sent to your email',
                status.HTTP_403_FORBIDDEN)
            mac_address = post_data.get('mac_address')
            if not mac_address:
                return CommonResponseObject.fail_response(
                'Please provide your MAC address', status.HTTP_412_PRECONDITION_FAILED)
            if user and bcrypt.check_password_hash(user.password, post_data.get('password')) :
                device = DeviceList.get_device_by_user_id_and_mac(user.id,mac_address)
                auth_token = DatabaseCheck.prepare_auth_token(user.id, mac_address,
                        None if not device else device.main_key)
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
                    DatabaseCheck.remove_key_pair(auth_token)
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

class ConfirmAPI(MethodView):
    """
    API is used for confirmation
    """
    def get(self, token):
        try:
            email = ConfirmationToken.confirm_token(token)
        except:
            return CommonResponseObject.fail_response(
                'The token is invalid or expired',
                status.HTTP_404_NOT_FOUND)
        user = User.query.filter_by(email=email).first_or_404()
        if user.is_confirmed:
            return CommonResponseObject.fail_response(
                'The user is confirmed, please login',
                status.HTTP_202_ACCEPTED)
        user.is_confirmed = True
        db.session.add(user)
        db.session.commit()
        return CommonResponseObject.success_resp_with_mess(
            'The user is successfully confirmed')



registration_view = RegisterAPI.as_view('register_api')
login_view = LoginAPI.as_view('login_api')
logout_view = LogoutAPI.as_view('logout_api')
status_view = TokenStatusAPI.as_view('status_api')
confirm_view = ConfirmAPI.as_view('confirm_api')
profile_view = ProfileAPI.as_view('profile_api')
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
auth_blueprint.add_url_rule(
    '/auth/confirm/<string:token>',
    view_func = confirm_view,
    methods=['GET']
)
auth_blueprint.add_url_rule(
    '/auth/profile',
    view_func = profile_view,
    methods=['GET,POST']
)
