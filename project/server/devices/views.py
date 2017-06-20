from flask import Blueprint, request, make_response, jsonify
from flask.views import MethodView
from project.server import  db
from flask_api import status
from project.server.helper import CommonResponseObject, RequestUtils
from project.server.models import User, DeviceList
devices_blueprint = Blueprint('devices', __name__)

class DeviceAPI(MethodView):
    """
    APIs to manage devices
    """
    def post(self):
        # Get the post data
        post_data = request.get_json()
        user = User.query.filter_by(email=post_data.get('email')).first()
        if not user:
            return CommonResponseObject.device_user_not_exist()
        device = DeviceList.query.filter_by(mac_address=post_data.get('mac_address')).first()
        if device:
            return CommonResponseObject.device_existed()
        try:
           device = DeviceList(
                user=user,
                mac_address=post_data.get('mac_address'),
                os=post_data.get('os')
            )
           db.session.add(device)
           db.session.commit()
           return CommonResponseObject.device_stored_success()
        except Exception as e:
           print(e)
           return CommonResponseObject.device_exception()

    def get(self):
        # Get the access token from the header
        auth_token = RequestUtils.get_access_token(request)
        if auth_token:
            response = User.decode_auth_token(auth_token)
            if not isinstance(response,str):
                device_list = DeviceList.query.filter(DeviceList.user.has(id=response))
                data = [device.serialize() for device in device_list]
                responseObject = {
                    'status': 'success',
                    'data': data
                }
                return make_response(jsonify(responseObject)), status.HTTP_200_OK
            responseObject = {
                'status': 'fail',
                'message': response
            }
            return make_response(jsonify(responseObject)), status.HTTP_401_UNAUTHORIZED
        else:
            responseObject={
                    'status': 'fail',
                    'message': 'Please provide a valid token'
            }
            return make_response(jsonify(responseObject)), status.HTTP_401_UNAUTHORIZED
class KeyAPI(MethodView):
    """
    Key API for retrieving backup key
    """
    def get(self):
        return None

devices_view = DeviceAPI.as_view('devices_api')
keys_view = KeyAPI.as_view('keys_api')
devices_blueprint.add_url_rule(
    '/devices',
    view_func=devices_view,
    methods=['GET','POST']
)
devices_blueprint.add_url_rule(
    '/devices/key',
    view_func=keys_view,
    methods=['GET','POST']
)
