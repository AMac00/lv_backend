from flask import request, jsonify, Blueprint, session
from flask import current_app as app
from flask_pymongo import PyMongo
import json
from bson.objectid import ObjectId
from datetime import datetime, timedelta
import logging
# Run local commands
import subprocess
# Clear loggs
import os, shutil, time
# Import Database for error logging
from .fun_db import log_transaction

# Database and PWD
mongo = PyMongo(app)
db = mongo.cx[app.config["MONGO_DBNAME_1"]]
__db_system__ = db.system
__db_transactions__ = db.transactions

class fun_system():

    def __init__(self):
        return

    def version(self):
        version = "0.1"
        return (version)

    # Todo: Add NGINX log clear
    # Todo: Add MongoDB log clear
    def system_log_purge_all(self,__info__):
        logging.debug("info = {0}".format(__info__))
        __return__ = {}
        __log_path__ = "/var/logvisualizer/lv_backend/logs/"
        __camserv_log__ = "camserv"
        # Remove LV_backend Logs
        try:
            if "clear" in __info__["LV_backend"].lower():
                __logs__ = [file for file in os.listdir(__log_path__)]
                for file in __logs__:
                    if ".log" in file:
                        f_file = os.path.join(__log_path__, file)
                        print("{0}".format(f_file))
                        os.remove(f_file)
                __return__["ae_backend-call_server"] = "success"
            __return__["status"] = "success"
        except:
            __return__['message'] = "Error deleting LV_backend logs = {0}.log".format(__log_path__)
            logging.debug("Error deleting LV_backend logs = {0}.log".format(__return__['message']))
            __return__["lv_backend_log_clear"] = "error"
            __return__["status"] = "Error"
        try:
            # Write to DB
            __log__ = {"status": __return__["status"],
                       "primary_action": "system",
                       "sub_action": "Clear logs",
                       "message": __return__['message']}
            log_transaction(__log__)
            return(__return__)
        except:
            logging.warning("Error writing to transaction Database")
            logging.warning("-------------------------------------")
            logging.warning("Log - {0}".format(__log__))
            return(__return__)

    # Get current service status
    def system_service_status_get(self,service):
        __return__ = {}
        __service_list__ = [service]
        try:
            for __service__ in __service_list__:
                try:
                    __status__ = subprocess.Popen(['systemctl', 'active', __service__], stdout=subprocess.PIPE)
                    (output, err) = __status__.communicate()
                    __return__[__service__] = output.decode('utf-8')
                except:
                    __return__[__service__] = 'Error getting status'
        except:
            __return__['err_msg'] = 'Error in the system_service_status_get '
            __return__['service_status'] = 'error'
        return(__return__)

    # Get current service status
    def system_service_status_reset(self,__service__):
        __return__ = {}
        try:
            logging.warning("Resetting {0}".format(__service__))
            __return__["service"] = 'Resetting {0}'.format(__service__)
            __status__ = subprocess.call("systemctl restart {0}".format(__service__), shell=True)
            time.sleep(2)
            try:
                __status__ = subprocess.Popen(['systemctl', 'is-active', __service__], stdout=subprocess.PIPE)
                (output, err) = __status__.communicate()
                __return__[__service__] = output.decode('utf-8')
                __return__["status"] = "success"
            except:
                __return__[__service__] = 'Error getting status = {0}'.format(__service__)
                __return__["status"] = "Error"
        except:
            __return__['err_msg'] = 'Error in the system {0} status_reset'.format(__service__)
            __return__['service_status'] = 'error'
            __return__["status"] = "Error"
        try:
            # Write to DB
            __log__ = {"status": __return__["status"],
                       "primary_action": "system",
                       "sub_action": "Service Reset",
                       "message": __return__[__service__]}
            log_transaction(__log__)
            return(__return__)
        except:
            logging.warning("Error writing to transaction Database")
            logging.warning("-------------------------------------")
            logging.warning("Log - {0}".format(__log__))
            return(__return__)

    # Get last items from transaction logs
    def system_transaction_log(self,__info__):
        __return__ = {}
        # Get last x transaction logs
        try:
            logging.debug("Start pulling the last transaction logs")
            __db_transaction__ = __db_transactions__.find({}, {"_id": 0}).sort('_id', -1).limit(int(__info__['records']))
            # __db_transaction__.sort('date', -1)
            __item__ = 0
            __items__ = {}
            # Pull Port list from DB
            for doc in __db_transaction__:
                # Bypass template
                if "transaction" in doc:
                    logging.debug("bypass template on transaction pull")
                else:
                    __items__[__item__] = doc
                    __item__ = __item__ + 1
            __return__['transactions'] = __items__
            __return__['status'] = 'success'
            __return__['total_logs'] = str(__item__)
        except:
            logging.warning("error with trans")
            __return__['status'] = 'error'
            __return__['err_msg'] = 'error pulling transaction logs'
        return(__return__)