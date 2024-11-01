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
api = Namespace('email', description='Email config related operations')



# Database and PWD
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


bp_logs_param = api.model("email", { 'matrix': fields.String(description="['EmailConfig']", required=True) })
bp_logs_param_save = api.model("email_data", { 'email_gateway': fields.String(description="['Email Gateway']", required=True), 
                                          'email_from': fields.String(description="['Email From']", required=True),
                                          'email_to': fields.String(description="['Email To']", required=True) })
bp_logs_param_test = api.model("email_test", { 'matrix': fields.String(description="['EmailTest']", required=True) })

'''  API - Routes '''

@api.route('/pull')
class logs(Resource):
    @api.expect(bp_logs_param)
    @api.doc(bp_logs_param)
    @jwt_required
    def post(selfs):
        __info__ = request.get_json()
        __fun_logging__ = fun_logging()
        __results__ = __fun_logging__.api_emailconfig_pull(__info__)
        return jsonify(__results__)

@api.route('/save')
class logs(Resource):
    @api.expect(bp_logs_param_save)
    @api.doc(bp_logs_param_save)
    @jwt_required
    def post(selfs):
        __info__ = request.get_json()
        __fun_logging__ = fun_logging()
        __results__ = __fun_logging__.api_emailconfig_save(__info__)
        return jsonify(__results__)

@api.route('/test')
class logs(Resource):
    @api.expect(bp_logs_param_test)
    @api.doc(bp_logs_param_test)
    @jwt_required
    def post(selfs):
        __info__ = request.get_json()
        __fun_logging__ = fun_logging()
        __results__ = __fun_logging__.api_emailconfig_test(__info__)
        return jsonify(__results__)

