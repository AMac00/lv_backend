from flask import request, jsonify, Blueprint
from flask import current_app as app
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, get_current_user
# Import standard Config for Seeding
from env_config import ProductionConfig
# Import supporting models
from models.fun_db import fun_db
from models.fun_users import fun_users
# Import RestPlus for API Documentation
from flask_restplus import fields, Resource, Namespace, Api
import logging
import time

# User Namespace
api = Namespace('system', description='System related operations')



# Database and PWD
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

'''  API - Routes '''

@api.route('/db/refresh')
class system_refresh_dbs(Resource):
    @api.expect()
    @api.doc()
    @jwt_required
    def post(selfs):
        __info__ = ProductionConfig
        db = fun_db()
        __results__ = db.db_preseed_system(__info__)
        return jsonify(__results__)

ns_system_db_param = api.model("Databae",
                                 {
                                     "element": fields.String(description="Element Name ", required=True),
                                     "element_value": fields.String(description="Element Value ", required=True)})

@api.route('/db/<col_name>')
class system_db_name(Resource):
    @api.expect()
    @api.doc()
    @jwt_required
    def get(selfs,col_name):
        db = fun_db()
        __results__ = db.db_get_content(col_name)
        return jsonify(__results__)

    @api.expect(ns_system_db_param)
    @api.doc(ns_system_db_param)
    @jwt_required
    def post(self,col_name):
        db = fun_db()
        __info__ = request.get_json()
        __info__["col_name"] = col_name
        __results__ = db.db_update_content(__info__)
        return jsonify(__results__)

    @api.expect()
    @api.doc()
    @jwt_required
    def delete(self, col_name):
        db = fun_db()
        __seed__ = ProductionConfig
        __info__ = {'col_name': col_name }
        __results__ = db.db_collection_drop(__seed__,__info__)
        return jsonify(__results__)

# @api.route('/services/<service>')
# class system_services(Resource):
#     ''' GET Current System Status '''
#     @api.expect()
#     @api.doc()
#     def get(selfs,service):
#         sys = fun_system()
#         __results__ = sys.system_service_status_get(service)
#         return jsonify(__results__)
#
#     ''' Update Current System Status '''
#     @api.expect()
#     @api.doc()
#     def post(selfs,service):
#         __info__ = request.get_json()
#         sys = fun_system()
#         __results__ = sys.system_service_status_reset(service)
#         return jsonify(__results__)

ns_system_logs_param = api.model("Clear Logs",
                                 {
                                    "AE_backend": fields.String(description="clear", required=False),
                                    "AE_frontEnd": fields.String(description="clear", required=False),
                                    "NGNIX": fields.String(description="clear", required=False),
                                    "MongoDB": fields.String(description="clear", required=False),
                                    "Call_server": fields.String(description="clear", required=False)})

# Application User API
ns_user_param = api.model("Users",
                                 {
                                     "usrid": fields.String(description="User ID", required=True),
                                     "password": fields.String(description="User Password", required=True)})



@api.route('/users/register')
class users_register(Resource):
    @api.expect(ns_user_param)
    @api.doc(ns_user_param)
    def post(selfs):
        __info__ = request.get_json()
        logging.debug("info = {0}".format(__info__))
        __fun_users__ = fun_users()
        __results__ = __fun_users__.register_users(__info__)
        return jsonify(__results__)

@api.route('/users/login')
class users_login(Resource):
    @api.expect(ns_user_param)
    @api.doc(ns_user_param)
    def post(selfs):
        __info__ = request.get_json()
        logging.debug("bp_system: info = {0}".format(__info__))
        __fun_users__ = fun_users()
        __results__ = __fun_users__.login_users(__info__)
        return jsonify(__results__)

@api.route('/users/<userid>')
class users_userid(Resource):
    '''
    Get User Information
    '''
    @api.expect()
    @api.doc(ns_user_param)
    @jwt_required
    def get(selfs):
        __info__ = request.get_json()
        __info__['usrid'] = userid
        __fun_users__ = fun_users()
        __results__ = __fun_users__.query_users(__info__)
        return jsonify({'result': __results__})
    '''
    Update User information
    '''
    @api.expect()
    @api.doc(ns_user_param)
    @jwt_required
    def post(selfs):
        __info__ = request.get_json()
        __info__['usrid'] = userid
        __fun_users__ = fun_users()
        __results__ = __fun_users__.update_users(__info__)
        return jsonify({'result': __results__})
    '''
    Delete User information
    '''
    @api.expect()
    @api.doc(ns_user_param)
    @jwt_required
    def delete(selfs):
        print("The current user is {0}".format(get_current_user()))
        __info__ = request.get_json()
        __info__['usrid'] = userid
        __fun_users__ = fun_users()
        __results__ = __fun_users__.remove_user(__info__)
        return jsonify({'result': __results__})
