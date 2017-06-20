from flask import  make_response, jsonify
from flask_api import status
class RequestUtils:
    @staticmethod
    def get_access_token(request):
        auth_header=request.headers.get('Authorization')
        if auth_header:
            return auth_header.split(" ")[1]
        return False
class CommonResponseObject:
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
    def login_success(auth_token):
        responseObject = {
            'status': 'success',
            'message': 'Successfully logged in.',
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

