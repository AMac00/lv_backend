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
api = Namespace('cdr_data', description='Get CUCM CDR data')



# Database and PWD
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


bp_logs_param = api.model("cdr_data", { 'matrix': fields.String(description="['i.e., CdrCall | CdrCallPrior']", required=True),
'timezone': fields.String(description="['Client Timezone. i.e., GMT-0600']", required=True),
'date': fields.String(description="['Date selected. i.e., 2022-02-15']", required=True) })

'''  API - Routes '''

@api.route('/pull')
class logs(Resource):
    @api.expect(bp_logs_param)
    @api.doc(bp_logs_param)
    @jwt_required
    def post(selfs):
        __info__ = request.get_json()
        __fun_logging__ = fun_logging()
        __results__ = __fun_logging__.api_cdr_pull(__info__)
        return jsonify(__results__)
