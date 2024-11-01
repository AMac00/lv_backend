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


# User Namespace
api = Namespace('logs', description='Logs related operations')



# Database and PWD
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

'''  API - Routes '''

@api.route('/pull')
class logs(Resource):
    @api.expect()
    @api.doc()
    def post(selfs):
        __info__ = {"temp":"temp"}
        # Todo : Pull Current configuration from DB
        # Todo : Kick off Pull Jobs
        # TODO : Return
        return jsonify()
