from flask import Blueprint
from Views import *

devices_blueprint = Blueprint('devices', __name__)
devices_view = DeviceAPI.as_view('devices_api')
keys_view = KeyAPI.as_view('keys_api')
req_authorize_view = RequestAuthorizeAPI.as_view('req_authorize_api')
req_otp_view = RequestOTPAPI.as_view('req_otp_api')
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
devices_blueprint.add_url_rule(
    '/key/root',
    view_func=keys_view,
    methods=['POST']
)
devices_blueprint.add_url_rule(
    '/devices/request-authorize',
    view_func=req_authorize_view,
    methods=['GET','POST']
)
devices_blueprint.add_url_rule(
    '/devices/request-otp',
    view_func=req_otp_view,
    methods=['POST']
)
