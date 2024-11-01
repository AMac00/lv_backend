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
from multiprocessing import Process

# User Namespace
api = Namespace('collect_log4snow', description='Collect logs for ServiceNow case')



# Database and PWD
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


bp_logs_param = api.model("collect_log4snow", { 'snow_instance': fields.String(description='ttec.service-now.com',  required=True), 'case': fields.String(description='ServiceNow case number. i.e., CS0001051', required=True), 'applications': fields.String(description="['cucm','vvb','fin','cvp','cvpvxml','rtr','pg']", required=True) })

def fire_and_forget(arg_one):  ## using multiprocessing module to run long job
    __fun_logging__ = fun_logging()
    __fun_logging__.api_log_push(arg_one)

'''  API - Routes '''

@api.route('/push')
class snow_logs(Resource):
    @api.expect(bp_logs_param)
    @api.doc(bp_logs_param)
    def post(selfs):
        __info__ = request.get_json()
        ##__fun_logging__ = fun_logging()
        ##__fun_logging__.api_log_push(__info__)
        p =  Process(target=fire_and_forget, args=(__info__, ))
        p.daemon = True
        p.start()
        __results__ = {'status':'OK'}
        return jsonify(__results__)
