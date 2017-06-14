from flask import Blueprint, request, make_response, jsonify
from flask.views import MethodView
from flask_api import status
from project.server import bcrypt, db
from project.server.models import User, BlacklistToken
auth_blueprint = Blueprint('auth', __name__)


class CommonResponseObject:
    @staticmethod
    def unauthorized_token_response():
        responseObject = {
            'status': 'fail',
            'message': 'Provide a valid auth token.'
        }
        return make_response(jsonify(responseObject)),status.HTTP_401_UNAUTHORIZED
    @staticmethod
    def forbiden_token_response():
        responseObject = {
            'status': 'fail',
            'message': 'Provide a valid auth token.'
        }
        return make_response(jsonify(responseObject)), status.HTTP_403_FORBIDDEN

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
        responseObject = {
            'status': 'fail',
            'message': 'Some error occurred. Please try again.'
        }
        return make_response(jsonify(responseObject)), status.HTTP_401_UNAUTHORIZED
    @staticmethod
    def register_user_exist():
        responseObject = {
            'status': 'fail',
            'message': 'User already exists. Please Log in.',
        }
        return make_response(jsonify(responseObject)), status.HTTP_202_ACCEPTED
    @staticmethod
    def login_success(auth_token):
        responseObject = {
            'status': 'success',
            'message': 'Successfully logged in.',
            'auth_token': auth_token.decode()
        }
        return make_response(jsonify(responseObject)), status.HTTP_200_OK
    @staticmethod
    def login_user_not_exist():
        responseObject = {
            'status': 'fail',
            'message': 'User does not exist.'
        }
        return make_response(jsonify(responseObject)), status.HTTP_404_NOT_FOUND
    @staticmethod
    def login_exception():
        responseObject = {
            'status': 'fail',
            'message': 'Try again'
        }
        return make_response(jsonify(responseObject)), status.HTTP_500_INTERNAL_SERVER_ERROR
    @staticmethod
    def logout_success():
        responseObject = {
            'status': 'success',
            'message': 'Successfully logged out.'
        }
        return make_response(jsonify(responseObject)), status.HTTP_200_OK
    @staticmethod
    def logout_exception(e):
        responseObject = {
            'status': 'fail',
            'message': e
        }
        return make_response(jsonify(responseObject)), status.HTTP_200_OK
    @staticmethod
    def token_response(resp):
        responseObject = {
            'status': 'fail',
            'message': resp
        }
        return make_response(jsonify(responseObject)), status.HTTP_401_UNAUTHORIZED

class RegisterAPI(MethodView):
    """
    User Registration Resource
    """

    def post(self):
        # get the post data
        post_data = request.get_json()
        # check if user already exists
        user = User.query.filter_by(email=post_data.get('email')).first()
        if not user:
            try:
                user = User(
                    email=post_data.get('email'),
                    password=post_data.get('password')
                )

                # insert the user
                db.session.add(user)
                db.session.commit()
                # generate the auth token
                auth_token = user.encode_auth_token(user.id, user.encrypted_key)
                return CommonResponseObject.register_success(auth_token)
            except Exception :
                return CommonResponseObject.register_exception()
        else:
            return CommonResponseObject.register_user_exist()
class LoginAPI(MethodView):
    """
    User Login Resource
    """
    def post(self):
        # get the post data
        post_data = request.get_json()
        try:
            # fetch the user data
            user = User.query.filter_by(
                email=post_data.get('email')
              ).first()
            if user and bcrypt.check_password_hash(
                    user.password, post_data.get('password')
            ):
                auth_token = user.encode_auth_token(user.id,user.encrypted_key)
                if auth_token:
                    return CommonResponseObject.login_success(auth_token)
            else:
                return CommonResponseObject.login_user_not_exist()
        except Exception as e:
            print(e)
            return CommonResponseObject.login_exception()
            # define the API resources
class UserAPI(MethodView):
    """
    User Resource
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
                user = User.query.filter_by(id=response).first()
                responseObject = {
                    'status': 'success',
                    'data': {
                        'user_id': user.id,
                        'email': user.email,
                        'admin': user.admin,
                        'registered_on': user.registered_on
                    }
                }
                return make_response(jsonify(responseObject)), status.HTTP_200_OK
            responseObject = {
                'status': 'fail',
                'message': response
            }
            return make_response(jsonify(responseObject)), status.HTTP_401_UNAUTHORIZED
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)),status.HTTP_401_UNAUTHORIZED
class LogoutAPI(MethodView):
    """
    Logout Resource
    """
    def post(self):
        # get auth token
        auth_header = request.headers.get('Authorization')
        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''
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
class EncryptedKeyAPI(MethodView):
    """
    Store and retrieve the encrypted key that is associated with the user
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
                user = User.query.filter_by(id=response).first()
                responseObject = {
                    'status': 'success',
                    'data': {
                        'encrypted_key': user.encrypted_key
                    }
                }
                return make_response(jsonify(responseObject)), status.HTTP_200_OK
            return CommonResponseObject.token_response()
        else:
            return CommonResponseObject.unauthorized_token_response()
    def post(self):
        auth_header = request.headers.get('Authorization')
        post_data = request.get_json()
        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''
        if auth_token:
            response = User.decode_auth_token(auth_token)
            if not isinstance(response,str):
                user = User.query.filter_by(id=response).first()
                if user.encrypted_key == None:
                    user.encrypted_key = post_data.get('encrypted_key')
                    db.session.commit()
                    responseObject = {
                        'status': 'success',
                        'message': 'Encrypted Key stored successfully'
                    }
                    return make_response(jsonify(responseObject)),status.HTTP_200_OK
                else:
                    responseObject = {
                        'status': 'fail',
                        'message': 'User is already assigned with a key'
                    }
                    return make_response(jsonify(responseObject)), status.HTTP_400_BAD_REQUEST
            else:
                return CommonResponseObject.unauthorized_token_response()
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
user_view = UserAPI.as_view('user_api')
logout_view = LogoutAPI.as_view('logout_api')
key_view = EncryptedKeyAPI.as_view('key_api')

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
    '/auth/status',
    view_func=user_view,
    methods=['GET']
)
auth_blueprint.add_url_rule(
    '/auth/logout',
    view_func=logout_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/key',
    view_func=key_view,
    methods=['GET','POST']
)
