import requests, urllib3, ssl
from urllib3.exceptions import HTTPError as BaseHTTPError
from requests.auth import HTTPBasicAuth
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
import paramiko
from paramiko_expect import SSHClientInteraction
import time
import traceback
import logging
# from .fun_db import log_transaction
from .fun_filemanagement import fun_file_management
from concurrent.futures import ThreadPoolExecutor, as_completed

import os
import shutil
import tarfile
import os.path
import re
import xml.etree.ElementTree as ET

from smb.SMBConnection import SMBConnection
from socket import gethostbyname
import socket
from pymongo import MongoClient
import urllib

## Mongo DB Connection ##
MONGO_SERVER = "127.0.0.1"
MONGO_PORT = "2727"
MONGO_DBNAME_1 = "lvdb"
MONGO_AUTH_SOURCE = 'admin'
MONGO_AUTH_MECHANISM = 'SCRAM-SHA-1'
MONGO_USERNAME = 'lvuser'
MONGO_PWD = 'password@123'
MONGO_URI = ("mongodb://{0}:{1}@{2}:{3}".format(MONGO_USERNAME, urllib.parse.quote("password@123"), MONGO_SERVER, MONGO_PORT))
client = MongoClient(MONGO_URI)
lvdb = client['lvdb']
__db_system__ = lvdb['system']
__db_transactions__ = lvdb['transactions']


class fun_applog():
    def __init__(self):
        return

    def __version__(self):
        __version__ = 0.1
        return(__version__)


    # This is the AXL pull request for pulling file from VOS instances
    def __fun_request__(self, __session__, __url__, __headers__, __payload__):
        ''' Threaded function for pulls'''
        __return__ = {}
        try:
            __method__ = "POST"
            logging.debug("URL = {0}".format(__url__))
            logging.debug(("{0} Payload is {1}".format(__method__, __payload__)))
            __response__ = __session__.request(__method__, __url__, headers=__headers__, data=__payload__, verify=False)
            logging.debug("Return Status Code = {0}".format(__response__.status_code))
            logging.debug("Return Message = {0}".format(__response__.text))
            if __response__.status_code == 200:
                logging.debug("Response Code = {0}".format(__response__.status_code))
                __body__ = BeautifulSoup(__response__.text, 'xml')
                logging.debug("Body Parse = {0}".format(__body__))
                __items__ = __body__.find('SetOfFiles')
                if not __items__:
                    __return__["message"] = "Didn't find any files to download for {0}, you might increase the timer.".format(__url__)
                    logging.warning(__return__["message"])
                    __return__["status"] = 'Error'
                    try:
                        # Write to DB
                        __log__ = {"status": __return__["status"],
                                   "primary_action": "Logging",
                                   "sub_action": "VOS Log Collection",
                                   "message": __return__['message']}
                        ## log_transaction(__log__)
                        return (__return__)
                    except:
                        logging.warning("Error writing to transaction Database")
                        logging.warning("-------------------------------------")
                        logging.warning("Log - {0}".format(__log__))
                        return (__return__)
                for __item__ in __items__.find_all('item'):
                    try:
                        logging.info("File = {0} Size= {1}".format(__item__.find('name').contents[0],
                                                                   __item__.find('filesize').contents[0]))
                    except:
                        pass
            elif __response__.status_code == 500:
                __body__ = BeautifulSoup(__response__.text, 'xml')
                __faultstring__ = __body__.find("faultstring")
                __return__['status'] = "Error"
                __return__["message"] = "Error - {0}".format(__faultstring__.contents[0])
                logging.error(__return__["message"])
            else:
                __return__['status'] = "Error"
                __return__["message"] ="Non standard request response = {0}".format(__response__.status_code)
                logging.error(__return__["message"])
        except requests.exceptions.HTTPError as errh:
            __return__['status'] = "Error"
            __return__["message"] = "Http Error:", errh
        except requests.exceptions.ConnectionError as errc:
            __return__['status'] = "Error"
            __return__["message"] = "Error Connecting:", errc
        except requests.exceptions.Timeout as errt:
            __return__['status'] = "Error"
            __return__["message"] = "Timeout Error:", errt
        except requests.exceptions.RequestException as err:
            __return__['status'] = "Error"
            __return__["message"] = "OOps: Something Else", err
            logging.error(__return__['message'])
        try:
            # Write to DB
            __log__ = {"status": __return__["status"],
                       "primary_action": "Logging",
                       "sub_action": "HTTP Log Collection",
                       "message": __return__['message']}
            ## log_transaction(__log__)
            return (__return__)
        except:
            logging.warning("Error writing to transaction Database")
            logging.warning("-------------------------------------")
            logging.warning("Log - {0}".format(__log__))
            return (__return__)

    ## SMB pull Helper functions
    @staticmethod
    def make_tarfile(output_filename, source_dir):
        with tarfile.open(output_filename, "w:gz") as tar:
            tar.add(source_dir, arcname=os.path.basename(source_dir))

    ## SMB pull Helper functions
    @staticmethod
    def remove_logs(dir_root, app_name):
        root_dir = dir_root + app_name # Directory to scan/delete

        keep = 'keep' # name of file in directory to not be deleted

        for root, dirs, files in os.walk(root_dir):
            for name in files:
                # make sure what you want to keep isn't in the full filename
                if (keep not in root and keep not in name):
                    os.unlink(os.path.join(root, name)) # Deletes files not in 'keep' 
            for name in dirs:
                if (keep not in root and keep not in name):
                    shutil.rmtree(os.path.join(root, name)) # Deletes directories not in 'keep' dir
    

    # # This is SSH pull request
    def __fun_ssh__(self, __vos_server__, __ssh_logs__, __settings_general__, __settings_servers__, time_offset_val):
        # Use SSH client to login
        try:
            __return__ = {}
            # Create a new SSH client object
            client = paramiko.SSHClient()
            # Set SSH key parameters to auto accept unknown hosts
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            logging.debug("Trying to connect to = {0}".format(__vos_server__))
            # Connect to the host
            # logging.debug("[jc] ssh => " + __settings_servers__["os_usr"] + "|" + __settings_servers__["os_pwd"])
            client.connect(hostname=__vos_server__, username=__settings_servers__["os_usr"], password=__settings_servers__["os_pwd"])
            __prompt__ = "admin:"
            logging.debug("Connected to = {0}".format(__vos_server__))
            # Create a client interaction class which will interact with the host
            with SSHClientInteraction(client, timeout=10, display=False) as interact:
                interact.expect(__prompt__, timeout=15)
                __log_file__ = 'file get activelog {0} reltime minutes {1}'.format(__ssh_logs__, time_offset_val)
                logging.debug("file active = {0}".format(__log_file__))
                # interact.send('file get activelog /uccx/log/MIVR/* reltime 60 minutes')
                interact.send(__log_file__)
                time.sleep(2)
                logging.debug("Waiting of y/no")
                interact.send("y")
                logging.debug("Sent {0}".format('Y'))
                interact.send(__settings_general__["sftp_server"])
                logging.debug("Sent {0}".format(__settings_general__["sftp_server"]))
                logging.debug("Sent {0}".format(__settings_general__["sftp_port"]))
                interact.send(__settings_general__["sftp_port"])
                logging.debug("Sent {0}".format(__settings_general__["sftp_port"]))
                interact.send(__settings_general__["sftp_usr"])
                logging.debug("Sent {0}".format(__settings_general__["sftp_usr"]))
                interact.send(__settings_general__["sftp_pwd"])
                logging.debug("Sent {0}".format(__settings_general__["sftp_pwd"]))
                interact.send(__settings_servers__["sftp_directory"].replace('instant/',''))
                logging.debug("Sent {0}".format(__settings_servers__["sftp_directory"].replace('instant/','')))
                interact.send("yes")
                interact.expect(__prompt__)
                __output__ = interact.current_output
                __return__['message'] = ("Downloaded files from {0}".format(__vos_server__))
                __return__["status"] = 'success'
                if "o files matched filter criteria" in __output__:
                    logging.error("{0} on {1} did NOT contain any files".format(__ssh_logs__, __vos_server__))
                    __return__['message'] = ("{0} on {1} did NOT contain any files".format(__ssh_logs__, __vos_server__))
                logging.debug("SSH output for {0} = {1}".format(__vos_server__, __output__))
                interact.send('exit')
                interact.expect()
                client.close()
        except:
            # traceback.print_exc()
            __return__["status"] = 'error'
            __return__['message'] = ("Error getting {0} from {1} via ssh = traceback = {2}".format(__ssh_logs__, __vos_server__,
                                                                              traceback.print_exc()))
            logging.error("Error getting {0} from {1} via ssh = traceback = {2}".format(__ssh_logs__, __vos_server__,
                                                                              traceback.print_exc()))
        try:
            # Write to DB
            __log__ = {"status": __return__["status"],
                       "primary_action": "logging",
                       "sub_action": "Sched ssh logging",
                       "message": __return__}
            ## log_transaction(__log__)
            return (__return__)
        except:
            logging.warning("Error writing to transaction Database")
            logging.warning("-------------------------------------")
            logging.warning("Log - {0}".format(__log__))
            return (__return__)



    ## Helper functions
    def getDurationInHours(self, sec):
        hours = divmod(sec, 3600)[0]
        return int(hours)

    ## Helper functions
    def ensure_dir(self, file_path):
        ##directory = os.path.dirname(file_path)
        try:
            if not os.path.exists(file_path):
                os.makedirs(file_path)
        except Exception as e:
            logging.error('Exception' + str(e))   
   
    
    ## Function for pulling PG logs
    def __fun_porticoPG__(self,__pg_server__,__settings_general__,__settings_servers__, time_offset_val,  __application_types__):
        __return__ = {}
        
        logTypes = {}
        sftpBasedDir = __settings_general__['sftp_upload_dir'] +  __application_types__ + '/'  ##  '/data/loguser/upload/instant/pg/'
        
        ## logTypeDict = __settings_servers__['log_portico']
        ## for key in logTypeDict:

        ## logging.debug('pg logs => ' + str(logTypes))
        ### Create directory is not existed ###
        logging.debug('create dir => ' + sftpBasedDir + __pg_server__)
        fun_applog.ensure_dir(self, sftpBasedDir + __pg_server__)

        __date_to__ = (datetime.now()).strftime('%s') + '000'
        __date_from__=  (datetime.now() - timedelta(minutes=int(time_offset_val))).strftime('%s') + '000'
        ## logging.debug('to date: ' + str(__date_to__) + ' |  from date: ' + str(__date_from__))
        username = __settings_servers__['os_usr']
        password = __settings_servers__['os_pwd']
        exceptionRaised =  False
        pg_log_list = []

        url = 'https://{0}:7890/icm-dp/rest/DiagnosticPortal/GetMenu'.format(__pg_server__)
        try:
            r = requests.get(url, auth=(username, password), verify=False)
            components =  re.search('<select name="Component" >(.*)</select></td></tr><tr><td></td><td><h3>Level:', r.text).group(1)
            logging.debug('web request return  => ' + components)
            e = ET.ElementTree(ET.fromstring('<root>' + components + '</root>'))
            for elt in e.iter():
                if elt.text is not None:
                    comp = elt.text
                    logging.debug('component:[{0}]'.format(comp))  ## elt.tag,
                    if ('ctisvr' in comp or 'pim1' in comp or 'jgw1' in comp):
                        if (comp not in pg_log_list):
                            pg_log_list.append(comp)
        except Exception as exx:
            exceptionRaised = True
            logging.error('Exception: ' + str(exx))
            __return__["status"] = 'error'
            __return__['message'] = ('Exception: ' + str(exx))

        for log_entry in pg_log_list:
            try:
                requestUrl = 'https://{0}:7890/icm-dp/rest/DiagnosticPortal/ListTraceFiles?Component={1}&FromDate={2}&ToDate={3}&UseTzadjustoff=NO'.format(__pg_server__, log_entry, str(__date_from__), str(__date_to__))
                logging.debug('requestUrl => ' + requestUrl)
                r = requests.get(requestUrl, auth=(username, password), verify=False) 
                logging.debug('PG return => ' + r.text) 
                logfile = re.search('<dp:FileProperty Date=(.*)Name=\"(.*)\" Size=', r.text).group(2)
                logging.debug('PG logfile => ' + logfile)
                r.close()  ## close connection

                download_file_url = 'https://{0}:7890/icm-dp/rest/DiagnosticPortal/DownloadTraceFile?Component={1}&File={2}'.format(__pg_server__, log_entry, logfile)
                logging.debug('PG download_file_url => ' + download_file_url)
                req = requests.get(download_file_url, auth=(username, password), verify=False)
                with open(sftpBasedDir + __pg_server__ + '/' + logfile, 'wb') as f:
                    f.write(req.content)
                req.close()

            except Exception as ex:
                exceptionRaised = True
                logging.error('Exception: ' + str(ex))
                __return__["status"] = 'error'
                __return__['message'] = ('Exception: ' + str(ex))

        if (exceptionRaised == False):
            __return__["status"] = 'success'
            __return__['message'] = ('Successfully pulled files from {0}'.format(__pg_server__))
 
        try:
            # Write transaction log to DB
            __log__ = {"status": __return__["status"],
                       "primary_action": "logging",
                       "sub_action": "Sched porticoPG logging",
                       "message": __return__['message']}
            ## log_transaction(__log__)
            return (__return__)
        except:
            logging.warning("Error writing to transaction Database")
            logging.warning("-------------------------------------")
            logging.warning("Log - {0}".format(__log__))
            return (__return__)


    ## Function for pulling Router logs
    def __fun_porticoRTR__(self,__rtr_server__,__settings_general__,__settings_servers__, time_offset_val,  __application_types__):
        __return__ = {}

        logTypes = {}
        sftpBasedDir = __settings_general__['sftp_instant_dir'] +  __application_types__ + '/'  ##  '/data/loguser/upload/instant/rtr/'


        logging.debug('create dir => ' + sftpBasedDir + __rtr_server__)
        fun_logging.ensure_dir(self, sftpBasedDir + __rtr_server__)

        __date_to__ = (datetime.now()).strftime('%s') + '000'
        __date_from__=  (datetime.now() - timedelta(minutes=int(time_offset_val))).strftime('%s') + '000'

        username = __settings_servers__['os_usr']
        password = __settings_servers__['os_pwd']
        exceptionRaised =  False
        rtr_log_list = []

        url = 'https://{0}:7890/icm-dp/rest/DiagnosticPortal/GetMenu'.format(__rtr_server__)
        try:
            r = requests.get(url, auth=(username, password), verify=False)
            components =  re.search('<select name="Component" >(.*)</select></td></tr><tr><td></td><td><h3>Level:', r.text).group(1)
            logging.debug('web request return  => ' + components)
            e = ET.ElementTree(ET.fromstring('<root>' + components + '</root>'))
            for elt in e.iter():
                if elt.text is not None:
                    comp = elt.text
                    logging.debug('component:[{0}]'.format(comp))  ## elt.tag,
                    if ('rtr' in comp or 'agi' in comp):
                        if (comp not in rtr_log_list):
                            rtr_log_list.append(comp)
        except Exception as exx:
            exceptionRaised = True
             __return__["status"] = 'error'
             __return__['message'] = ('Exception: ' + str(exx))

        for log_entry in rtr_log_list:
            try:
                requestUrl = 'https://{0}:7890/icm-dp/rest/DiagnosticPortal/ListTraceFiles?Component={1}&FromDate={2}&ToDate={3}&UseTzadjustoff=NO'.format(__rtr_server__, log_entry, str(__date_from__), str(__date_to__))
                logging.debug('requestUrl => ' + requestUrl)
                r = requests.get(requestUrl, auth=(username, password), verify=False)
                logging.debug('Router return => ' + r.text)
                logfile = re.search('<dp:FileProperty Date=(.*)Name=\"(.*)\" Size=', r.text).group(2)
                logging.debug('Router logfile => ' + logfile)
                r.close()  ## close connection

                download_file_url = 'https://{0}:7890/icm-dp/rest/DiagnosticPortal/DownloadTraceFile?Component={1}&File={2}'.format(__rtr_server__, log_entry, logfile)
                logging.debug('Router log download_file_url => ' + download_file_url)
                req = requests.get(download_file_url, auth=(username, password), verify=False)
                with open(sftpBasedDir + __rtr_server__ + '/' + logfile, 'wb') as f:
                    f.write(req.content)
                req.close()

            except Exception as ex:
                exceptionRaised = True
                logging.error('Exception: ' + str(ex))
                __return__["status"] = 'error'
                __return__['message'] = ('Exception: ' + str(ex))

        if (exceptionRaised == False):
            __return__["status"] = 'success'
            __return__['message'] = ('Successfully pulled files from {0}'.format(__rtr_server__))

        try:
            # Write transaction log to DB
            __log__ = {"status": __return__["status"],
                       "primary_action": "logging",
                       "sub_action": "Sched porticoRTR logging",
                       "message": __return__['message']}
            log_transaction(__log__)
            return (__return__)
        except:
            logging.warning("Error writing to transaction Database")
            logging.warning("-------------------------------------")
            logging.warning("Log - {0}".format(__log__))
            return (__return__)


    ## Function for pulling cvp vxml logs
    def __fun_smb__(self,__cvpvxml_server__,__settings_general__,__settings_servers__, time_offset_val,  __application_types__):
        __return__ = {}
        username = __settings_servers__['os_usr'] 
        password = __settings_servers__['os_pwd']
        domain = __settings_general__['smb_domain']      ## 'lab'
        port = __settings_general__['smb_port']               ## 445
        share_name = __settings_general__['smb_share_name']   ## 'CVP'
        toplevel = __settings_general__['smb_app_top_level']  ## '/VXMLServer/applications/'
        appArr = []
        logTypes = []
        sftpBasedDir = __settings_general__['sftp_upload_dir'] +  __application_types__ + '/'  ##  '/data/loguser/upload/cvpvxml/'
        logTimeThresholdInHr = int( int(time_offset_val) / 10 )    ## 24 hour in production
        logTypeDict = __settings_servers__['log_smb']
        for key in logTypeDict:
            logTypes.append(logTypeDict[key])
        logging.debug(username + '|xxxxxxx|' + domain + '|' +str(port) + '|' + share_name + '|' + toplevel + '|' + sftpBasedDir)
        try:
            conn = SMBConnection(username, password, socket.gethostname(),__cvpvxml_server__ , domain, is_direct_tcp=True)
            assert conn.connect(__cvpvxml_server__, port)
            ## logging.debug('[jc] after making smb connection ...')
            shares = conn.listShares()
            for share in shares:
                if (share.name == share_name):
                    sharedfiles = conn.listPath(share.name, toplevel)
                    for sharedfile in sharedfiles:
                        if (sharedfile.filename != '.' and sharedfile.filename != '..'):
                            appArr.append(sharedfile.filename)
                            ## logging.debug('[jc] after making smb connection ...' + sharedfile.filename)

            ### Create directory is not existed ###
            logging.debug('create dir => ' + sftpBasedDir + __cvpvxml_server__)
            fun_applog.ensure_dir(self, sftpBasedDir + __cvpvxml_server__)
            now = datetime.now()
            dt_str = now.strftime('%Y-%m-%d %H:%M:%S')
            for logtype in logTypes:
                for app in appArr:
                    ##ensure_dir(sftpBasedDir + __cvpvxml_server__  + '/' + app)
                    logDir = '/VXMLServer/applications/' + app + '/logs/' + logtype + '/'
                    ##logging.debug('logDir => ' + logDir)
                    for share in shares:
                        if (share.name == share_name):
                            sharedfiles = conn.listPath(share.name, logDir)
                            for sharedfile in sharedfiles:
                                if (sharedfile.filename != '.' and sharedfile.filename != '..'):
                                    if (fun_applog.getDurationInHours(self, (now - datetime.fromtimestamp(sharedfile.last_write_time)).total_seconds()) < logTimeThresholdInHr):
                                        ##logging.debug('converted time in utc: ' + sharedfile.filename + ' | '  + datetime.fromtimestamp(sharedfile.last_write_time).strftime('%Y-%m-%d %H:%M:%S'))
                                        dirDownload = sftpBasedDir + __cvpvxml_server__ + '/' + app + '/' + logtype
                                        ##logging.debug('create app dir => ' + sftpBasedDir + __cvpvxml_server__ + '/' + app)
                                        ##logging.debug('create download dir => ' +  dirDownload)
                                        fun_applog.ensure_dir(self, sftpBasedDir + __cvpvxml_server__ + '/' + app)
                                        fun_applog.ensure_dir(self, dirDownload)
                                        fileDownload =  dirDownload + '/' + sharedfile.filename
                                        with open(fileDownload, 'wb') as file_obj:
                                            conn.retrieveFile(share_name, logDir + sharedfile.filename, file_obj)
            conn.close()
            __return__["status"] = 'success'
            __return__['message'] = ('Successfully pulled files from {0}'.format(__cvpvxml_server__))
        except Exception as ex:
            logging.error('Exception: ' + str(ex))
            __return__["status"] = 'error'
            __return__['message'] = ('Exception: ' + str(ex))
        try:
            # Write to DB
            __log__ = {"status": __return__["status"],
                       "primary_action": "logging",
                       "sub_action": "Sched smb cvp logging",
                       "message": __return__['message']}
            ## log_transaction(__log__)
            return (__return__)
        except:
            logging.warning("Error writing to transaction Database")
            logging.warning("-------------------------------------")
            logging.warning("Log - {0}".format(__log__))
            return (__return__)


    ## Function for pulling cvp callsvr logs
    def __fun_smb_cvp__(self,__cvp_server__,__settings_general__,__settings_servers__, time_offset_val,  __application_types__):
        __return__ = {}
        username = __settings_servers__['os_usr']
        password = __settings_servers__['os_pwd']
        domain = __settings_general__['smb_domain']          ## 'lab'
        port = __settings_general__['smb_port']               ## 445
        share_name = __settings_general__['smb_share_name']   ## 'CVP'
        toplevel =  '/logs/'    ## __settings_general__['smb_app_top_level']  ## '/logs/'
        appArr = []
        logTypes = []
        logging.debug('application type = {0}'.format(__application_types__))
        sftpBasedDir = __settings_general__['sftp_upload_dir'] +  __application_types__ + '/'  ##  '/data/loguser/upload/cvp/'
        logTimeThresholdInHr = int( int(time_offset_val) / 10 )
        logTypeDict = __settings_servers__['log_smb']
        for key in logTypeDict:
            logTypes.append(logTypeDict[key])
        logging.debug(username + '|xxxxxxx|' + domain + '|' +str(port) + '|' + share_name + '|' + toplevel + '|' + sftpBasedDir)
        try:
            conn = SMBConnection(username, password, socket.gethostname(),__cvp_server__ , domain, is_direct_tcp=True)
            assert conn.connect(__cvp_server__, port)
            ## logging.debug('[jc] after making smb connection ...')
            shares = conn.listShares()
            

            ### Create directory is not existed ###
            logging.debug('create dir => ' + sftpBasedDir + __cvp_server__)
            fun_applog.ensure_dir(self, sftpBasedDir + __cvp_server__)
            now = datetime.now()
            dt_str = now.strftime('%Y-%m-%d %H:%M:%S')

            for share in shares:
                if (share.name == share_name):
                    sharedfiles = conn.listPath(share.name, toplevel)
                    for sharedfile in sharedfiles:
                        file_name = sharedfile.filename
                        if (file_name != '.' and file_name != '..' and (file_name.startswith('CVP.') or file_name.startswith('Error.'))):
                            if (fun_applog.getDurationInHours(self, (now - datetime.fromtimestamp(sharedfile.last_write_time)).total_seconds()) < logTimeThresholdInHr):
                                ##logging.debug('converted time in utc: ' + sharedfile.filename + ' | '  + datetime.fromtimestamp(sharedfile.last_write_time).strftime('%Y-%m-%d %H:%M:%S'))
                                dirDownload = sftpBasedDir + __cvp_server__
                                ##logging.debug('create app dir => ' + sftpBasedDir + __cvp_server__ )
                                ##logging.debug('create download dir => ' +  dirDownload)
                                ##fun_applog.ensure_dir(self, sftpBasedDir + __cvp_server__)
                                fun_applog.ensure_dir(self, dirDownload)
                                fileDownload =  dirDownload + '/' + file_name
                                with open(fileDownload, 'wb') as file_obj:
                                    conn.retrieveFile(share_name, toplevel + file_name, file_obj)
            conn.close()
            __return__["status"] = 'success'
            __return__['message'] = ('Successfully pulled cvp log files from {0}'.format(__cvp_server__))
        except Exception as ex:
            logging.error('Exception: ' + str(ex))
            __return__["status"] = 'error'
            __return__['message'] = ('Exception: ' + str(ex))
        try:
            # Write to DB
            __log__ = {"status": __return__["status"],
                       "primary_action": "logging",
                       "sub_action": "Sched smb cvpvxml logging",
                       "message": __return__['message']}
            ## log_transaction(__log__)
            return (__return__)
        except:
            logging.warning("Error writing to transaction Database")
            logging.warning("-------------------------------------")
            logging.warning("Log - {0}".format(__log__))
            return (__return__)


    # Threading Connection Function
    def __fun_logging_pull(self, __settings_general__,__settings_servers__, time_offset_val,  __application_types__):
        ## logging.debug("[jc] inside __fun_logging_pull")
        logging.debug("__settings_general__ = {0}".format(__settings_general__))
        logging.debug("__settings_servers__ = {0}".format(__settings_servers__))
        logging.debug("time_offset_val = {0}".format(str(time_offset_val)))

        ### Start collect logs ###
        try:
            if 'http' in __settings_servers__["log_connection"]:
                ''' Build Concatenate servicelog pulls '''
                __servicelog_items__ = ""
                for __servicelogs__ in __settings_servers__["log_http"]:
                    __servicelog_items__ = __servicelog_items__ + '<item xsi:type=\"xsd:string\">{0}</item>\r\n'.format(__servicelogs__)
                logging.debug(__servicelog_items__)
                ''' Build current working time '''
                __date_1__ = datetime.now()
                __to_time__ = ('<ToDate xsi:type=\"xsd:string\">{0}</ToDate>\r\n'.format(__date_1__.strftime("%m/%d/%Y %H:%M %p")))
                __date_2__=  __date_1__ - timedelta(minutes=int(time_offset_val))
                logging.debug("{0} = {1}".format("__date_1__",__date_1__))
                __from_time__ = ('<FromDate xsi:type=\"xsd:string\">{0}</FromDate>\r\n'.format(__date_2__.strftime("%m/%d/%Y %H:%M %p")))
                logging.debug("{0} = {1}".format("__date_2__", __date_2__))
                ''' Build sftp Information '''
                __sftp_timezone_ = ("{0}".format("(GMT-6:0) America/Chicago"))
                __sftp_port__ = ('<Port xsi:type=\"xsd:byte\">{0}</Port>\r\n '.format(__settings_general__['sftp_port']))
                __sftp_server__ = ('<IPAddress xsi:type=\"xsd:string\">{0}</IPAddress>\r\n'.format(__settings_general__['sftp_server']))
                __sftp_user__ = ('<UserName xsi:type=\"xsd:string\">{0}</UserName>\r\n'.format(__settings_general__['sftpuser']))
                __sftp_pwd__ = ('<Password xsi:type=\"xsd:string\">{0}</Password>\r\n  '.format(__settings_general__['sftppwd']))
                __sftp_zip__ = ('<ZipInfo xsi:type=\"xsd:boolean\">{0}</ZipInfo>\r\n'.format("false"))
                __sftp_dir__ = ('<RemoteFolder xsi:type=\"xsd:string\">{0}</RemoteFolder>\r\n'.format(__settings_servers__['sftpdirectory']))
                ''' Build full Body'''
                __payload__ = ('<soapenv:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:soap=\"http://schemas.cisco.com/ast/soap/\">\r\n   <soapenv:Header/>\r\n   <soapenv:Body>\r\n      <soap:SelectLogFiles soapenv:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n         <FileSelectionCriteria xsi:type=\"log:SchemaFileSelectionCriteria\" xmlns:log=\"http://cisco.com/ccm/serviceability/soap/LogCollection/\">\r\n            <ServiceLogs xsi:type=\"log:ArrayOfString\">\r\n            {0}\r\n            </ServiceLogs>\r\n            <SystemLogs xsi:type=\"log:ArrayOfString\">\r\n            </SystemLogs>\r\n            <SearchStr xsi:type=\"xsd:string\"></SearchStr>\r\n            <Frequency xsi:type=\"log:Frequency\">OnDemand</Frequency>\r\n            <JobType xsi:type=\"log:JobType\">PushtoSFTPServer</JobType>\r\n\t\t\t{1}\r\n            {2}\r\n            <TimeZone xsi:type=\"xsd:string\">Client: {3} </TimeZone>\r\n            <RelText xsi:type=\"log:RelText\">None</RelText>\r\n            <RelTime xsi:type=\"xsd:byte\">0</RelTime>\r\n            {4}\r\n            {5}\r\n            {6}\r\n            {7}\r\n            {8}\r\n            {9}\r\n         </FileSelectionCriteria>\r\n      </soap:SelectLogFiles>\r\n   </soapenv:Body>\r\n</soapenv:Envelope>'.format(__servicelog_items__,__to_time__,__from_time__,__sftp_timezone_,__sftp_port__,__sftp_server__,__sftp_user__,__sftp_pwd__,__sftp_zip__,__sftp_dir__))
                ''' Build Headers'''
                __headers__ = {
                    'Content-Type': 'text/xml;charset=utf-8',
                    'SOAPAction': '"http://schemas.cisco.com/ast/soap/action/#LogCollectionPort#LogCollectionPort"',
                }
                ''' Build Authentication'''
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                __session__ = requests.session()
                __session__.auth = HTTPBasicAuth(__settings_servers__["app_usr"], __settings_servers__["app_pwd"])
                ''' Build URL and Send Request'''
                with ThreadPoolExecutor(max_workers=100) as executor:
                    for __vos_server__ in __settings_servers__["servers"]:
                        __url__ = ('https://{0}:8443/logcollectionservice/services/LogCollectionPort'.format(__vos_server__))
                        executor.submit(fun_applog.__fun_request__(self,__session__,__url__, __headers__, __payload__))
        except Exception as ex:
            logging.error("{0}:{1} Schd HTTP is broken.. You might want to fix it.".format(__vos_server__, "__fun_logging_pull", str(ex)))
        

        # PUll directly from SSH ( required for VVB,CUCM,FIN ) 
        try:
            if 'ssh' in __settings_servers__["log_connection"]:
                with ThreadPoolExecutor(max_workers=100) as executor:
                    for __vos_server__ in __settings_servers__["servers"]:
                        for __ssh_logs__ in __settings_servers__["log_ssh"]:
                            executor.submit(fun_applog.__fun_ssh__(self,__vos_server__,__settings_servers__["log_ssh"][__ssh_logs__], __settings_general__,__settings_servers__, time_offset_val))
        except Exception as ex:
            logging.error("{0}:{1} SSH is broken.. You might want to fix it. Exception: {2}".format(__vos_server__,"__fun_logging_pull", str(ex)))
       
 
        # Perform log collection for CVP vxml 
        try:
            if 'smb' in __settings_servers__["log_connection"]:
                ## logging.debug("[jc] is a smb pull....")
                server_ip = ''
                if __application_types__ == 'cvpvxml':
                    with ThreadPoolExecutor(max_workers=100) as executor:
                        for __cvpvxml_server__ in __settings_servers__["servers"]:
                            fun_applog.__fun_smb__(self,__cvpvxml_server__,__settings_general__,__settings_servers__, time_offset_val,  __application_types__)
                elif __application_types__ == 'cvp':
                    with ThreadPoolExecutor(max_workers=100) as executor:
                        for __cvp_server__ in __settings_servers__["servers"]:
                            server_ip = __cvp_server__
                            fun_applog.__fun_smb_cvp__(self,__cvp_server__,__settings_general__,__settings_servers__, time_offset_val,  __application_types__)
        except Exception as ex:
            logging.error("{0}:{1} SMB is broken.. You might want to fix it. Exception: {2}".format(server_ip + '|' +  __application_types__,"__fun_logging_pull", str(ex)))


        # Perform log collection for PGs
        try:
            if 'porticoPG' in __settings_servers__["log_connection"]:
                ## logging.debug("[jc] start a pg portico pull....")
                with ThreadPoolExecutor(max_workers=100) as executor:
                    for __pg_server__ in __settings_servers__["servers"]:
                        fun_applog.__fun_porticoPG__(self,__pg_server__,__settings_general__,__settings_servers__, time_offset_val,  __application_types__)
        except Exception as ex:
            logging.error("{0}:{1} sched porticoPG web collection is broken.. You might want to fix it. Exception: {2}".format(__pg_server__,"__fun_logging_pull", str(ex)))


        # Perform log collection for Routers
        try:
            if 'porticoRTR' in __settings_servers__["log_connection"]:
                ## logging.debug("[jc] start a RTR portico pull....")
                with ThreadPoolExecutor(max_workers=100) as executor:
                    for __rtr_server__ in __settings_servers__["servers"]:
                        fun_applog.__fun_porticoRTR__(self,__rtr_server__,__settings_general__,__settings_servers__, time_offset_val,  __application_types__)
        except Exception as ex:
            logging.error("{0}:{1} sched porticoRTR web collection is broken.. You might want to fix it. Exception: {2}".format(__rtr_server__,"__fun_logging_pull", str(ex)))

    

    def clean_logs(self):
        try:
            __settings_general__ = __db_system__.find_one({'app': 'general'}, {"_id": 0})
            sftp_upload_dir = __settings_general__['app_settings']['sftp_upload_dir']
            log_age = __settings_general__['app_settings']['log_age']
            fun_file_management( sftp_upload_dir, log_age )
        except Exception as ex:
            logging.debug('Exception: [clean_logs] - {0}'.format(str(ex))) 
        return

    # Scheduled Pull function
    def sched_logging_pull(self,__info__):
        # Standard Return
        __return__ = {}
        try:

            ### Pull all the defautl global information
            __settings_general__ = __db_system__.find_one({'app': 'general'}, {"_id": 0})
            ### PUll all default information for all the selected Applications 
            __app_split__ = __info__['applications'].split(",")
            __settings_applications__ = {}
            for __applications__ in __app_split__:
                logging.debug("PUll {0} from DB".format(__applications__))
                __items_list__ = __db_system__.find_one({'app': __applications__.lower()}, {"_id": 0})
                logging.debug("PUlled {0} from DB".format(__items_list__))
                logging.debug("Count is greater then 1")
                __settings_applications__[__applications__] = __items_list__
                logging.debug("Servers for {0}".format(__applications__))
                logging.debug("Are {0}".format(__settings_applications__[__applications__]['app_settings']['servers']))
        except Exception as exx:
            __return__["status"] = "Error"
            __return__['message'] = "Error pulling System information from the DB" + str(exx)
            logging.warning("{0} - {1}".format(__return__["status"],__return__['message']))
            return (__return__)
        try:
            ### BEGIN ###
            tic = time.time()    ## start timeer
            time_offset_val = __settings_general__['app_settings']['offset_time']          ## __info__["offset_time"]
            with ThreadPoolExecutor(max_workers=100) as executor:
                for __application_types__ in __settings_applications__:
                    logging.debug("Sched Start Pulling {0} Threads".format(__application_types__))
                    src_dir = __settings_general__['app_settings']['sftp_upload_dir'] + (__settings_applications__[__application_types__]['app_settings']['sftp_directory']).replace('instant/','')

                    ## step 2 -  start log collection thread
                    executor.submit(fun_applog.__fun_logging_pull(self, __settings_general__['app_settings'], __settings_applications__[__application_types__]['app_settings'], time_offset_val, __application_types__))

            logging.debug("Total time for functions = {0}".format(time.time() - tic))
            ### END ###
            __return__["status"] = "Success"
            __return__["message"] = "Completed schedule log pulling process"
        except Exception as ex:
            __return__["status"] = "Error"
            __return__['message'] = "Error in schedule pulling Application from master function" + str(ex)
            logging.warning("{0} - {1}".format(__return__["status"],__return__['message']))
        try:
            # Write to DB
            __log__ = {"status": __return__["status"],
                       "primary_action": "logging",
                       "sub_action": "Sched Logging",
                       "message": __return__}
            ## log_transaction(__log__)
            return (__return__)
        except:
            logging.warning("Error writing to transaction Database")
            logging.warning("-------------------------------------")
            logging.warning("Log - {0}".format(__log__))
            return (__return__)


