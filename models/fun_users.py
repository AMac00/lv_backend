from flask import current_app as app
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from datetime import datetime, timedelta
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token
import logging
import time
# Import Database for error logging
from .fun_db import log_transaction
import ldap
import requests 

from env_config import ProductionConfig

# Database and PWD
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


class fun_users():

    def __init__(self):
        #__file__ = '{0}.log'.format(time.strftime("%m-%d-%Y_%H"))
        #logging.basicConfig(filename='/var/logvisualizer/lv_backend/logs/{0}'.format(__file__), level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', datefmt='%d-%b-%y %H:%M:%S')

        return

    def version(self):
        version = "0.1"
        return (version)

    def sso_login(self, user, pw, idpentryurl, homeRealmSelection, rdpurl, login_domain):
        try:
            sslverification = False
            session = requests.Session() 

            username = login_domain + '\\' + user
            password = pw

            headers = {'User-Agent': 'Mozilla/5.0', 'Content-Type':'application/x-www-form-urlencoded', 'Connection':'keep-alive', 'Referer':idpentryurl}  ## 'origin':domain,

            payloadSignIn = {'SignInIdpSite':'SignInIdpSite','SignInSubmit':'Sign+in','SingleSignOut':'SingleSignOut'}
            result0 = session.post(idpentryurl, headers=headers, data=payloadSignIn, verify = sslverification)
            reqCookie = session.cookies.get_dict()
	
            payloadLogin = {'UserName':username,'Password':password,'AuthMethod':'FormsAuthentication'}

            headers = {'User-Agent': 'Mozilla/5.0', 'Content-Type':'application/x-www-form-urlencoded', 'Connection':'keep-alive','Cookie':'MSISSamlRequest=' + reqCookie['MSISSamlRequest'],  'Referer':rdpurl}    
            result2 = session.post(rdpurl, headers=headers, data=payloadLogin, verify = sslverification)
            #print(session.cookies.get_dict())
            #print('[http post 3 response headers] => ' + str(result2.headers))
            #print(result2.status_code)
            #print(result2.text)
            if 'You are signed in.' in result2.text:
                ##print('User ({0}) is authenticated!!!'.format(username))
                return True
            else:
                ##print('User ({0}) is not authenticated!!!'.format(username))
                return False
	  
        except Exception as ex:
            #print('Exception: {0}'.format(str(ex)))
            return False


    def register_users(self, __info__):
        __return__ = {}
        # Check for user First before building a user
        try:
            logging.debug("Create user info = {0}".format(__info__))
            __results__ = fun_users.query_users(self, __info__)
            if "None" not in __results__["usrid"]:
                __return__['status'] = "error"
                __return__['err_msg'] = ("{0} is already registered".format(__info__['usrid']))
                logging.debug("{0} is already logged in, do nothing.".format(__info__['usrid']))
                return(__return__)
            else:
                logging.debug("{0} need to be created - Lets work on that.".format(__info__['usrid']))
        except:
            logging.debug("{0}".format('There was an error in the create user pre-user validation function'))
            __return__ = {"Error": "There was an error in the create user pre-user validation function"}
            return (__return__)
        # Create User
        try:
            db = mongo.cx[app.config["MONGO_DBNAME_1"]]
            users = db.users
            usrid = __info__['usrid']
            password = bcrypt.generate_password_hash(__info__['password']).decode('utf-8')
            created = datetime.utcnow()
            try:
                logging.debug("{0}".format('Inserting - Now'))
                user_id = users.insert({
                    'usrid': usrid,
                    'password': password,
                    'created': created
                })
                logging.debug("USER CREATED = {0}".format(usrid))
            except:
                logging.debug("{0}".format('Error Inserting new record for user'))
                pass
            logging.debug("{0}".format('Checking Post Insert - Now'))
            # Check for users after created
            try:
                new_user = users.find_one({'_id': user_id})
                __return__ = {'usrid': new_user['usrid'] + ' registered',
                              'status': 'success'}
            except:
                __return__ = {'usrid': new_user['usrid'] + ' registered',
                              'status': 'success'}
        except:
            __return__ = {'usrid': new_user['usrid'] + ' NOT registered',
                          'status': 'error',
                          'err_msg': "There was an error in creating the new user"}
        try:
            # Write to DB
            __log__ = {"status": __return__["status"],
                       "primary_action": "user",
                       "sub_action": "Register User",
                       "message": __return__}
            log_transaction(__log__)
            return (__return__)
        except:
            logging.warning("Error writing to transaction Database")
            logging.warning("-------------------------------------")
            logging.warning("Log - {0}".format(__log__))
            return (__return__)

    def query_users(self,__info__):
        __return__ = {}
        try:
            db = mongo.cx[app.config["MONGO_DBNAME_1"]]
            users = db.users
            login = __info__['usrid']
            __results__ = users.find_one({"usrid": login})
            if __results__ is None:
                __return__ = {
                    "usrid": "None",
                    'password': "None",
                }
            else:
                for x in __results__:
                    try:
                        # String is required because the Mongo ID is an object return.
                        __return__[x] = str(__results__[x])
                    except:
                        pass
            '''
            __return__ = {
                    "usrid": "None",
                    'password': "None",
            }
            '''
        except:
            __return__ = {
                "usrid": "None",
                'password': "None",
            }
            logging.debug('Failed to find the user {0}'.format(__info__['login']))
        return(__return__)

    def remove_user(self,__info__):
        __return__ = {}
        # Check for user First before building a user
        try:
            logging.debug("{0}".format(__info__))
            __results__ = fun_users.query_users(self, __info__)
            logging.debug("__results__ = {0}".format(__results__))
            if "None" in __results__["usrid"]:
                __return__ = {"usrid": "{0} Is not current a User.".format(__info__["usrid"])}
                return(__return__)
        except:
            __return__ = {"Error": "Error with the search for user function"}
            return (__return__)
        # Delete Record
        try:
            db = mongo.cx[app.config["MONGO_DBNAME_1"]]
            users = db.users
            logging.debug("results = {0}".format(__results__))
            __results__ = users.delete_one({'_id': ObjectId(__results__['_id'])})
            logging.debug("-----------------------")
            logging.debug("results = {0}".format(__results__))
            logging.debug("-----------------------")
            logging.debug("Deleted count =  {0}".format(__results__.deleted_count))
            if __results__.deleted_count <= 1 :
                __return__ = {"usrid": "{0} was removed.".format(__info__["usrid"]),
                                "status":"success",
                                "message": "{0} was removed.".format(__info__["usrid"])}
        except:
            logging.debug("error deleting keep testing")
            __return__ = {"usrid": "{0} was NOT removed - error in function.".format(__info__["usrid"]),
                          "status": "error",
                            "message": "{0} was NOT removed.".format(__info__["usrid"])}
            pass
        try:
            # Write to DB
            __log__ = {"status": __return__["status"],
                       "primary_action": "user",
                       "sub_action": "Register User",
                       "message": __return__["message"]}
            log_transaction(__log__)
            return (__return__)
        except:
            logging.warning("Error writing to transaction Database")
            logging.warning("-------------------------------------")
            logging.warning("Log - {0}".format(__log__))
            return (__return__)

    def update_users(self,__info__):
        __return__ = {}
        # Check for user First before building a user
        try:
            db = mongo.cx[app.config["MONGO_DBNAME_1"]]
            users = db.users
            __results__ = fun_users.query_users(self, __info__)
            if "None" in __results__["usrid"]:
                __return__ = {'usrid': __info__['usrid'] + ' is not found the the DB'}
                return(__return__)
            else:
                logging.debug("{0} is found and read for update.".format(__info__['usrid']))
        except:
            logging.debug("{0}".format('There was an error in the update user pre-user validation function'))
            __return__ = {"Error": "There was an error in the update user pre-user validation function"}
            return (__return__)
        try:
            # Update Elements
            __id__ = __results__['_id']
            __debugging__ = 1
            __results__.update(__info__)
            # remove extra's
            __results__.pop("debugging")
            __results__.pop("_id")
            # Test and Update Passwords
            if __results__["password"]:
                new_password = bcrypt.generate_password_hash(__results__['password']).decode('utf-8')
                __results__['password'] = new_password
            user_id = users.update_one({"_id": ObjectId(__id__)}, {"$set": __results__})
            __return__ = {"usrid": "update status = {0}".format(user_id.acknowledged)}
        except:
            __return__ = {'usrid': __info__['usrid'] + ' was NOT updated',
                          'Error': "There was an error in updating the user"}
        return(__return__)

    def login_users(self, __info__):
        __return__ = {}
        try:
            logging.warning("fun_users: login info = {0}".format(__info__))
            if ('usrid' not in __info__) or (__info__['usrid'] == ''):
                __return__['err_msg'] = "Missing {0}".format('usrid')
                __return__["status"] = "error"
                __return__["authenticated"] = False
                return(__return__)
            if ('password' not in __info__) or (__info__['password'] == ''):
                __return__['err_msg'] = "Missing {0}".format('password')
                __return__["status"] = "error"
                __return__["authenticated"] = False
                return (__return__)
        except:
            logging.warning("Error in Login form check")
            __return__['err_msg'] = "Error in form check".format('usrid')
            __return__["status"] = "error"
            __return__["authenticated"] = False
            return (__return__)
        try:
            db = mongo.cx[app.config["MONGO_DBNAME_1"]]
            __db_system__ = db.system
            __settings_general__ = __db_system__.find_one({'app': 'general'}, {"_id": 0})

            users = db.users
            login = __info__['usrid']
            password = __info__['password']
            __return__ = {}
            response = users.find_one({'usrid': login})
            if response:
                if bcrypt.check_password_hash(response['password'], password):
                    expires = timedelta(minutes=1360)
                    access_token = create_access_token(identity={
                        'iat': datetime.utcnow(),  # Issue date
                        "exp": datetime.utcnow() + timedelta(minutes=1360),  # DO NOT CHANGE THIS POSITION-VUE_isValidJwT
                        'usrid': response['usrid'],
                    }, expires_delta=expires)
                    __return__['token'] = access_token
                    __return__["authenticated"] = True
                    __return__['message'] = "{0} successfully logged in".format(response['usrid'])
                    __return__["status"] = "success"
                else:
                    __return__['message'] = "{0} attempted to login, Invalid credentials".format(__info__['usrid'])
                    __return__['err_msg'] = "{0} was found, please check credentials".format(__info__['usrid'])
                    __return__["status"] = "error"
                    __return__["authenticated"] = False
            else:
                if not __settings_general__['app_settings']['ldap_use']:
                    __return__['err_msg'] = "{0} was not found, please check username".format(__info__['usrid'])
                    __return__['message'] = "{0} attempted to login, unknown user".format(__info__['usrid'])
                    __return__["status"] = "error"
                    __return__["authenticated"] = False
                    return(__return__)
                 
                ## Otherwise start LDAP check login user ## 
                try:
                    logging.debug("Start LDAPS check for login user...") 
                    username = __info__['usrid']
                    password = __info__['password']
                    #logging.debug("Test01")
                    LDAP_SERVER = 'ldaps://' + __settings_general__['app_settings']['ldap_server'] + ':636'
                    #logging.debug("Test02")
                    # fully qualified AD user name
                    LDAP_USERNAME =  username + '@' + __settings_general__['app_settings']['ldap_domain']
                    logging.debug("LDAPS login user: " + LDAP_USERNAME)
                    # your password
                    LDAP_PASSWORD =  password
                    # base_dn = __settings_general__['app_settings']['ldap_base_dn']
                    # ldap_filter = 'userPrincipalName=' + username + '@' + __settings_general__['app_settings']['ldap_domain']
                    # attrs = ['memberOf']
                    # build a client
                    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
                    ldap_client = ldap.initialize(LDAP_SERVER)
                    #logging.debug("Test04")
                    # perform a synchronous bind
                    ldap_client.set_option(ldap.OPT_REFERRALS,0)
                    ldap_client.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
                    ldap_client.set_option(ldap.OPT_X_TLS,ldap.OPT_X_TLS_DEMAND)
                    ldap_client.set_option( ldap.OPT_X_TLS_DEMAND, True )
                    ldap_client.set_option( ldap.OPT_DEBUG_LEVEL, 255 )
                    #logging.debug("Test05 - {0} , {1}".format(LDAP_USERNAME,LDAP_PASSWORD))
                    ldap_client.simple_bind_s(LDAP_USERNAME, LDAP_PASSWORD)
                    #logging.debug("Test06")
                    logging.debug('User {0} authenticated!'.format(LDAP_USERNAME))
                    expires = timedelta(minutes=30)
                    access_token = create_access_token(identity={
                        'iat': datetime.utcnow(),  # Issue date
                        "exp": datetime.utcnow() + timedelta(minutes=360),  # DO NOT CHANGE THIS POSITION-VUE_isValidJwT
                        'usrid': username,
                    }, expires_delta=expires)
                    __return__['token'] = access_token
                    __return__["authenticated"] = True
                    __return__['message'] = "{0} successfully logged in".format(username)
                    __return__["status"] = "success"

                except ldap.INVALID_CREDENTIALS:
                    ldap_client.unbind()
                    try:
                        logging.debug("Start Tenant LDAPS check for login user...")
                        username = __info__['usrid']
                        password = __info__['password']
                        LDAP_SERVER = 'ldaps://' + __settings_general__['app_settings']['ldap_tenant_server'] + ':636'
                        LDAP_USERNAME =  username + '@' + __settings_general__['app_settings']['ldap_tenant_domain']
                        logging.debug("LDAPS login user: " + LDAP_USERNAME)
                        LDAP_PASSWORD =  password
                        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
                        ldap_client = ldap.initialize(LDAP_SERVER)
                        ldap_client.set_option(ldap.OPT_REFERRALS,0)
                        ldap_client.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
                        ldap_client.set_option(ldap.OPT_X_TLS,ldap.OPT_X_TLS_DEMAND)
                        ldap_client.set_option( ldap.OPT_X_TLS_DEMAND, True )
                        ldap_client.set_option( ldap.OPT_DEBUG_LEVEL, 255 )
                        ldap_client.simple_bind_s(LDAP_USERNAME, LDAP_PASSWORD)
                        logging.debug('User {0} authenticated!'.format(LDAP_USERNAME))
                        expires = timedelta(minutes=30)
                        access_token = create_access_token(identity={
                            'iat': datetime.utcnow(),  # Issue date
                            "exp": datetime.utcnow() + timedelta(minutes=360),  # DO NOT CHANGE THIS POSITION-VUE_isValidJwT
                            'usrid': username,
                        }, expires_delta=expires)
                        __return__['token'] = access_token
                        __return__["authenticated"] = True
                        __return__['message'] = "{0} successfully logged in".format(username)
                        __return__["status"] = "success"
                    except ldap.INVALID_CREDENTIALS:
                        __return__['message'] = "{0} attempted to login, Invalid credentials".format(__info__['usrid'])
                        __return__['err_msg'] = "{0} was found, please check credentials".format(__info__['usrid'])
                        __return__["status"] = "error"
                        __return__["authenticated"] = False

                except ldap.SERVER_DOWN:
                    __return__['err_msg'] = "LDAP Server is down"
                    __return__['message'] = "{0} attempted to login, unknown user".format(__info__['usrid'])
                    __return__["status"] = "error"
                    __return__["authenticated"] = False 
                except:
                    ldap_client.unbind()
                    __return__['err_msg'] = "{0} was not found, please check username".format(__info__['usrid'])
                    __return__['message'] = "{0} attempted to login, unknown user".format(__info__['usrid'])
                    __return__["status"] = "error"
                    __return__["authenticated"] = False
        except:
            __return__['Error'] = "There was a function error at {0}".format("login")
            __return__["authenticated"] = False
        # Write to Transaction Log
        __log__ = "empty log"
        try:
            # Write to DB
            __log__ = {"status": __return__["status"],
                       "primary_action": "Authentication",
                       "sub_action": "Login",
                       "message": __return__['message']}
            log_transaction(__log__)
            return(__return__)
        except:
            logging.warning("Error writing to transaction Database")
            logging.warning("-------------------------------------")
            logging.warning("Log - {0}".format(__log__))
            return(__return__)

