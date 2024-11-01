from flask import request, jsonify, Blueprint
from flask import current_app as app
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, get_current_user
from env_config import ProductionConfig
from models.fun_logging import fun_logging
from models.fun_users import fun_users
from flask_restplus import fields, Resource, Namespace, Api
import logging

# User Namespace
api = Namespace('collect_tenant_data', description='Collect tenant service status')


# Database and PWD
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


bp_logs_param = api.model("collect_tenant_data", { 'tenant_svc_status': fields.String(description='service status',  required=True) })

'''  API - Routes '''

@api.route('/push')
class GetTenantSvc(Resource):
    @api.expect(bp_logs_param)
    @api.doc(bp_logs_param)
    def post(selfs):
        __info__ = request.get_json()
        __fun_logging__ = fun_logging()
        __fun_logging__.api_tenant_svc_push(__info__)
        __results__ = {'status':'OK'}
        return jsonify(__results__)
