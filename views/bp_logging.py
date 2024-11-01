from flask import request, jsonify, Blueprint
from flask import current_app as app
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, get_current_user
# Import standard Config for Seeding
from env_config import ProductionConfig
# Import supporting models
from models.fun_logging import fun_logging
from models.fun_users import fun_users
# Import RestPlus for API Documentation
from flask_restplus import fields, Resource, Namespace, Api
import logging


# User Namespace
api = Namespace('logs', description='Logs related operations')



# Database and PWD
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


bp_logs_param = api.model("Logging",
                                 {
                                     "offset_time": fields.String(description="Time of Logs to pull", required=True),
                                     "instant": fields.String(description="Pull files instantly", required=True),
                                     'applications': fields.String(description="['cucm','vvb','fin','unity','cvp','cvpvxml','rtr','pg','livedata']")})

'''  API - Routes '''

@api.route('/pull')
class logs(Resource):
    @api.expect(bp_logs_param)
    @api.doc(bp_logs_param)
    @jwt_required
    def post(selfs):
        __info__ = request.get_json()
        __fun_logging__ = fun_logging()
        __results__ = __fun_logging__.api_logging_pull(__info__)
        return jsonify(__results__)
