from flask import request, jsonify, Blueprint, session
from flask import current_app as app
from flask_pymongo import PyMongo
import json
from bson.objectid import ObjectId
from datetime import datetime, timedelta
import logging
import subprocess
from datetime import time, date


# Database and PWD
mongo = PyMongo(app)
db = mongo.cx[app.config["MONGO_DBNAME_1"]]



class fun_db():

    def __init__(self):
        return

    def version(self):
        version = "0.1"
        return (version)

    # Pre Seed the DB
    def db_preseed_system(self,__info__):
        __return__ = {}
        # Pre-Seed System DB
        logging.debug("info = {0}".format(__info__))
        try:
            __collection_list__ = {
                                    'users': __info__.USERS_CONFIG}
            logging.debug("__collection_list__ = {0}".format(__collection_list__))
            for __collection__ in __collection_list__:
                try:
                    if __collection__ in db.list_collection_names():
                        try:
                            logging.debug("Drop {0} Collection".format(__collection__))
                            __return__[__collection__ + "_drop"] = "Yes"
                            db[__collection__].drop()
                        except:
                            logging.debug("Error dropping DB {0}".format(__collection__))
                    # Recreate the Collection
                    __db_collection__ = db[__collection__]
                    logging.debug("Recreate {0} Collection".format(__collection__))
                    # Recreate the DB
                    __results__ = __db_collection__.insert_one(__collection_list__[__collection__])
                    __return__[__collection__] = "recreated"
                except:
                    logging.warning("Error with preseeding {0} DB".format(__collection__))
                    __return__[__collection__] = "error recreating"
            __return__['status'] = "success"
        except:
            logging.warning("Error with preseeding function DB")
            __return__['status'] = "error"
            __return__['err_msg'] = 'Error in reseeding dbs function'
        __log__ = "empty log"
        try:
            # Write to DB
            __log__ = {"status": __return__["status"],
                       "primary_action": "Database",
                       "sub_action": "reseed",
                       "message": __return__}
            log_transaction(__log__)
            return(__return__)
        except:
            logging.warning("Error writing to transaction Database")
            logging.warning("-------------------------------------")
            logging.warning("Log - {0}".format(__log__))
            return(__return__)

    # Drop DB
    def db_collection_drop(self,__seed__,__info__):
        __return__ = {}
        # Pre-Seed System DB
        logging.debug("info = {0}".format(__info__))
        try:
            __collection_list__ = {
                                    'users': __info__.USERS_CONFIG}
            try:
                if __info__['col_name'] in db.list_collection_names():
                    try:
                        logging.debug("Drop {0} Collection".format(__info__['col_name']))
                        __return__[__info__['col_name'] + "_drop"] = "Yes"
                        db[__info__['col_name']].drop()
                    except:
                        logging.debug("Error dropping DB {0}".format(__info__['col_name']))
                # Recreate the Collection
                __db_collection__ = db[__info__['col_name']]
                logging.debug("Recreate {0} Collection".format(__info__['col_name']))
                # Recreate the DB
                __results__ = __db_collection__.insert_one(__collection_list__[__info__['col_name']])
                __return__[__info__['col_name']] = "recreated"
                __return__['status'] = "success"
            except:
                logging.warning("Error with preseeding {0} DB".format(__info__['col_name']))
                __return__[__info__['col_name']] = "error recreating"
                __return__['status'] = "error"
                __return__['err_msg'] = 'Error in dropping {0}'.format(__info__['col_name'])
        except:
            logging.warning("Error with dropping {0} function DB".format(__info__['col_name']))
            __return__['status'] = "error"
            __return__['err_msg'] = 'Error in dropping {0} function'.format(__info__['col_name'])
        # Write to Transaction Log
        __log__ = "empty log"
        try:
            # Write to DB
            __log__ = {"status": __return__["status"],
                       "primary_action": "Database",
                       "sub_action": "drop",
                       "message": __return__['message']}
            log_transaction(__log__)
            return(__return__)
        except:
            logging.warning("Error writing to transaction Database")
            logging.warning("-------------------------------------")
            logging.warning("Log - {0}".format(__log__))
            return(__return__)



    # Pull content of Database
    def db_get_content(self,col_name):
        __return__ = {}
        # Pull database information
        try:
            logging.debug("Database to pull {0}".format(col_name))
            __col_name__ = db[col_name]
            __increase__ = 1
            for __data__ in __col_name__.find({}, {'_id': False}):
                logging.debug("DB = {0}".format(__data__))
                __return__[str(__increase__)] = __data__
                __increase__ = __increase__ + 1
            return(__return__)
        except:
            logging.warning("Error with DG content pull function DB = {0}".format(col_name))
            __return__['status'] = "error"
            return(__return__)

    # Pull content of Database
    def db_update_content(self,__info__):
        __return__ = {}
        # Pull database information
        try:
            logging.debug("Database to update {0}".format(__info__))
            __col_name__ = db[__info__["col_name"]]
            # Update
            for __data__ in __col_name__.find():
                logging.debug("DBFunction - Update {0} = {1} in DB {2}".format(__info__['element'],__info__['element_value'],__info__['col_name']))
                __col_name__.update({"_id": __data__['_id']},{"$set": {__info__['element']: __info__['element_value']}})
            # Pull Data after the updates
            __increase__ = 1
            for __data__ in __col_name__.find({}, {'_id': False}):
                __return__[str(__increase__)] = __data__
                __increase__ = __increase__ + 1
            return(__return__)
        except:
            logging.warning("Error with DG content pull function DB = {0}".format(__info__['col_name']))
            __return__['status'] = "error"
            return(__return__)

class log_transaction():

    #Writing to Transation Log
    def __init__(self, __info__):
        try:
            # Set Time for action
            __date_time__ = datetime.now()
            __info__['date'] = '{0}'.format(__date_time__.strftime("%d-%m-%Y"))
            __info__['time'] = '{0}'.format(__date_time__.strftime("%H:%M:%S"))
            # Set Collection for DB
            __col_name__ = db.transactions
            __results__ = __col_name__.insert_one(__info__)
        except:
            logging.warning("Error writing to transaction DB = {0}".format(__info__))
        return

    def logging_buid(self,__info__):
        try:
            # Write to DB
            __log__ = {"status": __info__["status"],
                       "primary_action": __info__["primary-action"],
                       "sub_action": __info__['sub-action'],
                       "message": __info__['message']}
            fun_db.log_transaction(self,__log__)
        except:
            logging.warning("Error writing to transaction Database")
            logging.warning("-------------------------------------")
            logging.warning("Log - {0}".format(__log__))
        return()

class call_transactions():

    #Writing to Transation Log
    def __init__(self, __info__):
        try:
            __return__ = {}
            # Set Time for action
            __date_time__ = datetime.now()
            __info__['date'] = '{0}'.format(__date_time__.strftime("%d-%m-%Y"))
            __info__['time'] = '{0}'.format(__date_time__.strftime("%H:%M:%S"))
            # Validate if there a call record already, Create or update
            try:
                logging.debug("call_transactions Start")
                __col_name__ = db.calls
                logging.debug("call_transactions __col_name__ = {0}".format(__col_name__))
                # Validate there is a call reference ID to lookup
                if __info__["call_reference_id"]:
                    logging.debug('DBFunction - call_transactions __info__["call_reference_id"] = {0}'.format(__info__["call_reference_id"]))
                    # Only used if there is an error
                    __return__["message"] = "Error updating current call statistics callid = {0}".format(
                        __info__["call_reference_id"])
                    __call_id__ = __col_name__.find_one({'call_reference_id': __info__["call_reference_id"]})
                    # Check if the call ID was seen in the system:
                    if __call_id__:
                        logging.debug('DBFunction - GET call_transactions__call_id__ = {0}, find return = {1}'.format("update one", __call_id__))
                        for __element__ in __info__:
                            __col_name__.update({"_id": __call_id__['_id']},
                                                {"$set": {__element__: __info__[__element__]}})
                    # Didn't find call ID, we need to add a record
                    else:
                        logging.debug('DBFunction - Didnt find call_transactions__call_id__ = {0}'.format("insert one"))
                        __col_name__.insert_one(__info__)
            except:
                # Write to Transaction Log
                try:
                    # Write to DB
                    __log__ = {"status": 'error',
                               "primary_action": "Phone",
                               "sub_action": "call transactions",
                               "message": __return__["message"]}
                    logging.warning("Warning = {0}".format(__log__))
                    log_transaction(__log__)
                except:
                    logging.warning("Error writing to transaction Database")
                    logging.warning("-------------------------------------")
                    logging.warning("Log - {0}".format(__log__))
        except:
            logging.warning("Error writing to transaction DB = {0}".format(__info__))
