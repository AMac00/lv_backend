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
api = Namespace('directory', description='LDAP directory numbers related operations')



# Database and PWD
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


bp_logs_param_dn = api.model("directory_numbers", { 'matrix': fields.String(description="['DirectoryNum']", required=True), 'region': fields.String(description="['Directory Region']", required=True) })

bp_logs_param_dn_saved = api.model("directory_numbers_saved", { 'matrix': fields.String(description="['DirectoryNum']", required=True), 'cn': fields.String(description="['Directory Name']", required=True), 'cn': fields.String(description="['Directory Name']", required=True), 'phone': fields.String(description="['Phone Number']", required=True), 'mobile': fields.String(description="['Mobile Number']", required=True) })


'''  API - Routes '''

@api.route('/regions')
class logs(Resource):
    @jwt_required
    def post(selfs):
        __fun_logging__ = fun_logging()
        __results__ = __fun_logging__.api_directory_regions()
        return jsonify(__results__)

@api.route('/numbers')
class logs(Resource):
    @api.expect(bp_logs_param_dn)
    @api.doc(bp_logs_param_dn)
    @jwt_required
    def post(selfs):
        __info__ = request.get_json()
        __fun_logging__ = fun_logging()
        __results__ = __fun_logging__.api_directory_num(__info__)
        return jsonify(__results__)

@api.route('/save')
class logs(Resource):
    @api.expect(bp_logs_param_dn_saved)
    @api.doc(bp_logs_param_dn_saved)
    @jwt_required
    def post(selfs):
        __info__ = request.get_json()
        __fun_logging__ = fun_logging()
        __results__ = __fun_logging__.api_directory_num_save(__info__)
        return jsonify(__results__)

