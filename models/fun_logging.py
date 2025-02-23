from flask import current_app as app
from flask_pymongo import PyMongo
import requests, urllib3, ssl
from urllib3.exceptions import HTTPError as BaseHTTPError
from requests.auth import HTTPBasicAuth
from datetime import datetime, timedelta, date, tzinfo
from bs4 import BeautifulSoup
import paramiko
from paramiko_expect import SSHClientInteraction
import time
import traceback
import logging
# Import Database for error logging
from .fun_db import log_transaction
# Threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import os
import subprocess
import gzip
import zipfile

import shutil
import tarfile
import os.path
import re
import xml.etree.ElementTree as ET

from smb.SMBConnection import SMBConnection
from socket import gethostbyname
import socket
import pytz
import smtplib
import ldap, ldap.schema

# Database and PWD
mongo = PyMongo(app)
db = mongo.cx[app.config["MONGO_DBNAME_1"]]
__db_system__ = db.system
__db_transactions__ = db.transactions


class fun_logging():

    def __version__(self):
        __version__ = 0.2
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
                        log_transaction(__log__)
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
            log_transaction(__log__)
            return (__return__)
        except:
            logging.warning("Error writing to transaction Database")
            logging.warning("-------------------------------------")
            logging.warning("Log - {0}".format(__log__))
            return (__return__)

    ## SMB pull Helper functions
    @staticmethod
    def make_tarfile(output_filename, source_dir):
        ## added code to decode .gzo file and bundle raw text log into tar ball

        result = []
        for root, subdirectories, files in os.walk(source_dir):
            for subdirectory in subdirectories:
                result.append(os.path.join(root, subdirectory))

        result.sort()

        for dir in result:
            for filename in os.listdir(dir):
                if (filename.endswith('.gzo')):
                    tokens =  filename.split('.gzo')
                    file = tokens[0]
                    system_cmd = ("zcat {0} > {1}.log").format(os.path.join(dir,filename), os.path.join(dir,file))
                    logging.debug("Command to run = {0}".format(system_cmd))
                    with open("{0}.log".format(os.path.join(dir,file)), "w") as f:
                        subprocess.call(["/usr/bin/zcat", os.path.join(dir,filename)], stdout=f)
                    logging.debug("zcat Command ran sucessfully!")
                    ### clean up zip log ###
                    if os.path.exists(os.path.join(dir,filename)):
                        os.remove(os.path.join(dir,filename))
                elif (filename.endswith('.gz')):
                    tokens =  filename.split('.gz')
                    file = tokens[0]
                    with gzip.open( os.path.join(dir,filename), 'rb') as f_in:
                        with open( os.path.join(dir,file) +'.log','wb') as f_out:
                            shutil.copyfileobj(f_in,f_out)
                    logging.debug("gunzip Command ran sucessfully!")
                    ### clean up zip log ###
                    if os.path.exists(os.path.join(dir,filename)):
                        os.remove(os.path.join(dir,filename))
                elif (filename.endswith('.zip')):
                    tokens =  filename.split('.zip')
                    file = tokens[0]
                    with zipfile.ZipFile(os.path.join(dir,filename),"r") as zip_ref:
                        zip_ref.extractall(dir) 
                    logging.debug("unzip Command ran sucessfully!")
                    ### clean up zip log ###
                    if os.path.exists(os.path.join(dir,filename)):
                        os.remove(os.path.join(dir,filename))


        with tarfile.open(output_filename, "w:") as tar:
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
    def __fun_ssh__(self, __vos_server__, __ssh_logs__, __settings_general__, __settings_servers__, time_offset_val, logType):
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
                if ('livedata' in logType or 'clientlogs' in logType):  ## for Livedata and finesse log collection
                    __log_file__ = 'file get activelog {0}'.format(__ssh_logs__)
                ##elif ('clc' in logType):    ## for Cloud Connect log colletion
                ##    __log_file__ = 'file get activelog {0}'.format(__ssh_logs__)

                logging.debug("file active = {0}".format(__log_file__))
                # interact.send('file get activelog /uccx/log/MIVR/* reltime minutes 60')
                interact.send(__log_file__)
                time.sleep(2)
                logging.debug("Waiting of y/no")
                interact.send("y")
                logging.debug("Sent {0}".format('Y'))
                interact.send(__settings_general__["sftp_server"])
                logging.debug("Sent {0}".format(__settings_general__["sftp_server"]))
                interact.send(__settings_general__["sftp_port"])
                logging.debug("Sent {0}".format(__settings_general__["sftp_port"]))
                interact.send(__settings_general__["sftp_usr"])
                logging.debug("Sent {0}".format(__settings_general__["sftp_usr"]))
                interact.send(__settings_general__["sftp_pwd"])
                logging.debug("Sent {0}".format(__settings_general__["sftp_pwd"]))
                interact.send(__settings_servers__["sftp_directory"])
                logging.debug("Sent {0}".format(__settings_servers__["sftp_directory"]))
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
                       "sub_action": "ssh logging",
                       "message": __return__}
            log_transaction(__log__)
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
        sftpBasedDir = __settings_general__['sftp_instant_dir'] +  __application_types__ + '/'  ##  '/data/loguser/upload/instant/pg/'
        
        ## logTypeDict = __settings_servers__['log_portico']
        ## for key in logTypeDict:

        ## logging.debug('pg logs => ' + str(logTypes))
        ### Create directory is not existed ###
        logging.debug('create dir => ' + sftpBasedDir + __pg_server__)
        fun_logging.ensure_dir(self, sftpBasedDir + __pg_server__)

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
                       "sub_action": "portico logging",
                       "message": __return__['message']}
            log_transaction(__log__)
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
            logging.error('Exception: ' + str(exx))
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
                       "sub_action": "porticoRtr logging",
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
        sftpBasedDir = __settings_general__['sftp_instant_dir'] +  __application_types__ + '/'  ##  '/data/loguser/upload/instant/cvpvxml/'
        logTimeThresholdInHr = 2 ## int( int(time_offset_val) / 10 )    ## 24 hour in production
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
            fun_logging.ensure_dir(self, sftpBasedDir + __cvpvxml_server__)
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
                                    if (fun_logging.getDurationInHours(self, (now - datetime.fromtimestamp(sharedfile.last_write_time)).total_seconds()) < logTimeThresholdInHr):
                                        ##logging.debug('converted time in utc: ' + sharedfile.filename + ' | '  + datetime.fromtimestamp(sharedfile.last_write_time).strftime('%Y-%m-%d %H:%M:%S'))
                                        dirDownload = sftpBasedDir + __cvpvxml_server__ + '/' + app + '/' + logtype
                                        ##logging.debug('create app dir => ' + sftpBasedDir + __cvpvxml_server__ + '/' + app)
                                        ##logging.debug('create download dir => ' +  dirDownload)
                                        fun_logging.ensure_dir(self, sftpBasedDir + __cvpvxml_server__ + '/' + app)
                                        fun_logging.ensure_dir(self, dirDownload)
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
                       "sub_action": "smb cvpvxml logging",
                       "message": __return__['message']}
            log_transaction(__log__)
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
        sftpBasedDir = __settings_general__['sftp_instant_dir'] +  __application_types__ + '/'  ##  '/data/loguser/upload/instant/cvp/'
        logTimeThresholdInHr = 2  ##int( int(time_offset_val) / 10 )   
        logTypeDict = __settings_servers__['log_smb']
        for key in logTypeDict:
            logTypes.append(logTypeDict[key])
        logging.debug(username + '|xxxxxxx|' + domain + '|' +str(port) + '|' + share_name + '|' + toplevel + '|' + sftpBasedDir)
        try:
            conn = SMBConnection(username, password, socket.gethostname(),__cvp_server__ , domain, is_direct_tcp=True)
            assert conn.connect(__cvp_server__, port)
            ## logging.debug('[jc] after making smb connection ...')
            shares = conn.listShares()
            '''
            for share in shares:
                if (share.name == share_name):
                    sharedfiles = conn.listPath(share.name, toplevel)
                    for sharedfile in sharedfiles:
                        file_name = sharedfile.filename
                        if (file_name != '.' and file_name != '..' and (file_name.startswith('CVP.') or file_name.startswith('Error.'))):
                            logging.debug('[jc] cvp log files ...' + file_name)
            '''


            ### Create directory is not existed ###
            logging.debug('create dir => ' + sftpBasedDir + __cvp_server__)
            fun_logging.ensure_dir(self, sftpBasedDir + __cvp_server__)
            now = datetime.now()
            dt_str = now.strftime('%Y-%m-%d %H:%M:%S')
            
            for share in shares:
                if (share.name == share_name):
                    sharedfiles = conn.listPath(share.name, toplevel)
                    for sharedfile in sharedfiles:
                        file_name = sharedfile.filename
                        if (file_name != '.' and file_name != '..' and (file_name.startswith('CVP.') or file_name.startswith('Error.'))):
                            if (fun_logging.getDurationInHours(self, (now - datetime.fromtimestamp(sharedfile.last_write_time)).total_seconds()) < logTimeThresholdInHr):
                                ##logging.debug('converted time in utc: ' + sharedfile.filename + ' | '  + datetime.fromtimestamp(sharedfile.last_write_time).strftime('%Y-%m-%d %H:%M:%S'))
                                dirDownload = sftpBasedDir + __cvp_server__
                                ##logging.debug('create app dir => ' + sftpBasedDir + __cvp_server__ )
                                ##logging.debug('create download dir => ' +  dirDownload)
                                ##fun_logging.ensure_dir(self, sftpBasedDir + __cvp_server__)
                                fun_logging.ensure_dir(self, dirDownload)
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
                       "sub_action": "smb cvp logging",
                       "message": __return__['message']}
            log_transaction(__log__)
            return (__return__)
        except:
            logging.warning("Error writing to transaction Database")
            logging.warning("-------------------------------------")
            logging.warning("Log - {0}".format(__log__))
            return (__return__)



    # Threading Connection Function
    def __fun_logging_pull(self, __settings_general__,__settings_servers__, time_offset_val,  __application_types__, out_file, src_dir, remove_dir):
        ## logging.debug("[jc] inside __fun_logging_pull")
        logging.debug("__settings_general__ = {0}".format(__settings_general__))
        logging.debug("__settings_servers__ = {0}".format(__settings_servers__))
        logging.debug("time_offset_val = {0}".format(str(time_offset_val)))
        logging.debug("[tar] out_file  => " + out_file )
        logging.debug("[tar] src_dir  => " + src_dir )
        try:
            ## step 1 -  remove all logs
            fun_logging.remove_logs(remove_dir, __application_types__)
            ## step 2 -  collect application logs
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
                        executor.submit(fun_logging.__fun_request__(self,__session__,__url__, __headers__, __payload__))
                ## step 3 -  upload logs to web share
                fun_logging.make_tarfile(out_file,src_dir)
        except Exception as ex:
            logging.error("{0}:{1} HTTP is broken.. You might want to fix it.".format(__vos_server__, "__fun_logging_pull", str(ex)))
            ## return
        # PUll directly from SSH ( required for VVB,CUCM,FIN ) - short term until they fix it.
        try:
            if 'ssh' in __settings_servers__["log_connection"]:
                with ThreadPoolExecutor(max_workers=100) as executor:
                    for __vos_server__ in __settings_servers__["servers"]:
                        for __ssh_logs__ in __settings_servers__["log_ssh"]:
                            executor.submit(fun_logging.__fun_ssh__(self,__vos_server__,__settings_servers__["log_ssh"][__ssh_logs__], __settings_general__,__settings_servers__, time_offset_val, __ssh_logs__))
                ## step 3 -  upload logs to web share
                fun_logging.make_tarfile(out_file,src_dir)
        except Exception as ex:
            logging.error("{0}:{1} SSH is broken.. You might want to fix it. Exception: {2}".format(__vos_server__,"__fun_logging_pull", str(ex)))
            ## return
        
        # Perform log collection for CVP vxml 
        try:
            if 'smb' in __settings_servers__["log_connection"]:
                logging.debug("Is a smb pull....")
                server_ip = ''
                if __application_types__ == 'cvpvxml':
                    with ThreadPoolExecutor(max_workers=100) as executor:
                        for __cvpvxml_server__ in __settings_servers__["servers"]:
                            server_ip = __cvpvxml_server__
                            fun_logging.__fun_smb__(self,__cvpvxml_server__,__settings_general__,__settings_servers__, time_offset_val,  __application_types__)
                elif __application_types__ == 'cvp':
                    with ThreadPoolExecutor(max_workers=100) as executor:
                        for __cvp_server__ in __settings_servers__["servers"]:
                            server_ip = __cvp_server__ 
                            fun_logging.__fun_smb_cvp__(self,__cvp_server__,__settings_general__,__settings_servers__, time_offset_val,  __application_types__)
                ## step 3 -  upload logs to web share
                fun_logging.make_tarfile(out_file,src_dir)
        except Exception as ex:
            logging.error("{0}:{1} SMB is broken.. You might want to fix it. Exception: {2}".format(server_ip + '|' +  __application_types__,"__fun_logging_pull", str(ex)))

        # Perform log collection for PGs
        try:
            if 'porticoPG' in __settings_servers__["log_connection"]:
                ## logging.debug("[jc] start a pg portico pull....")
                with ThreadPoolExecutor(max_workers=100) as executor:
                    for __pg_server__ in __settings_servers__["servers"]:
                        fun_logging.__fun_porticoPG__(self,__pg_server__,__settings_general__,__settings_servers__, time_offset_val,  __application_types__)
                ## step 3 -  upload logs to web share
                fun_logging.make_tarfile(out_file,src_dir)
        except Exception as ex:
            logging.error("{0}:{1} PG portico web collection is broken.. You might want to fix it. Exception: {2}".format(__pg_server__,"__fun_logging_pull", str(ex)))
        
        # Perform log collection for CCE Routers
        try:
            if 'porticoRTR' in __settings_servers__["log_connection"]:
                ## logging.debug("[jc] start a router portico pull....")
                with ThreadPoolExecutor(max_workers=100) as executor:
                    for __rtr_server__ in __settings_servers__["servers"]:
                        fun_logging.__fun_porticoRTR__(self,__rtr_server__,__settings_general__,__settings_servers__, time_offset_val,  __application_types__)
                ## step 3 -  upload logs to web share
                fun_logging.make_tarfile(out_file,src_dir)
        except Exception as ex:
            logging.error("{0}:{1} RTR portico web collection is broken.. You might want to fix it. Exception: {2}".format(__rtr_server__,"__fun_logging_pull", str(ex)))


    # API Pull function
    def api_logging_pull(self,__info__):
        # Standard Return
        __return__ = {}
        try:
            # TODO: Pull "ServiceLogs", "time_offset", "sftpserver", "sftport", "sftpuser", "sftpdirectory","app_srv", "app_usr", "app_pwd","log_connection" from the DB

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
            time_offset_val =  __info__["offset_time"]
            with ThreadPoolExecutor(max_workers=100) as executor:
                for __application_types__ in __settings_applications__:
                    logging.debug("Start Pulling {0} Threads".format(__application_types__))
                    ##logging.debug("[jc] => " + str(__settings_general__['app_settings']))
                    ##logging.debug("[jc] => " + str(__settings_applications__[__application_types__]['app_settings']))
                    ## step 1 -  remove all logs
                    ## fun_logging.remove_logs(__settings_general__['app_settings']['sftp_instant_dir'], __application_types__)
                    out_file = __settings_general__['app_settings']['web_share_dir'] + __application_types__  + '-' + time_offset_val + '.tar'
                    src_dir = __settings_general__['app_settings']['sftp_upload_dir'] + __settings_applications__[__application_types__]['app_settings']['sftp_directory']
                    remove_dir = __settings_general__['app_settings']['sftp_instant_dir'] 
                    ## step 2 -  start log collection thread
                    executor.submit(fun_logging.__fun_logging_pull(self, __settings_general__['app_settings'], __settings_applications__[__application_types__]['app_settings'], time_offset_val, __application_types__, out_file, src_dir, remove_dir))
                    ## step 3 -  upload logs to web share
                    ## logging.debug("[tar] out_file  => " + out_file )
                    ## logging.debug("[tar] src_dir  => " + src_dir )
                    ##  fun_logging.make_tarfile(out_file,src_dir)

            logging.debug("Total time for functions = {0}".format(time.time() - tic))
            ### END ###
            __return__["status"] = "Success"
            __return__["message"] = "Completed log pulling process"
        except Exception as ex:
            __return__["status"] = "Error"
            __return__['message'] = "Error pulling Application from master function" + str(ex)
            logging.warning("{0} - {1}".format(__return__["status"],__return__['message']))
        try:
            # Write to DB
            __log__ = {"status": __return__["status"],
                       "primary_action": "logging",
                       "sub_action": "Api Logging",
                       "message": __return__}
            log_transaction(__log__)
            return (__return__)
        except:
            logging.warning("Error writing to transaction Database")
            logging.warning("-------------------------------------")
            logging.warning("Log - {0}".format(__log__))
            return (__return__)



    ## API CUCM CDR Pull functions ##
    def api_cdr_pull(self,__info__):
        # Standard Return
        __return__ = {}
        try:
            ### Pull all the defautl global information
            logging.debug("api passed in payload: {0}".format(__info__))
            __collRef__ = db.ccmcdr

            timezone = __info__['timezone'] ## GMT-(\d+)\d\d$ GMT-0600
            timezone = re.search('GMT-(\d+)\d\d$', timezone).group(1)
            logging.debug("api passed in (timezone) in payload: {0}".format(timezone))
           
            dayDiff = 1   ## default value
            client_time_str = (datetime.now(tz=pytz.UTC) - timedelta(hours=int(timezone))).strftime("%Y-%m-%d") + ' '  +  timezone + ':00:00'
            logging.debug("client_time_str: {0}".format(client_time_str))
            client_unix_time = int((datetime.strptime(client_time_str, '%Y-%m-%d %H:%M:%S')).timestamp()) 

            last24hr_utc_time =int((datetime.utcnow() - timedelta(hours=24)).timestamp()) ## 2-18-2022 | added | jchen | pull data 24 hrs

            if __info__['matrix'] == 'CdrCallPrior':
                daySelected = __info__['date']
                delta = datetime.strptime(client_time_str, '%Y-%m-%d %H:%M:%S') - datetime.strptime(daySelected + ' '  +  timezone + ':00:00', '%Y-%m-%d %H:%M:%S')
                logging.debug("client_time_str [today]: {0}".format(client_time_str))
                logging.debug("client_time_str [selected]: {0}".format(daySelected + ' '  +  timezone + ':00:00'))
                dayDiff = delta.days
                logging.debug("dayDiff: {0}".format(str(dayDiff)))
                client_unix_time_prior = int((datetime.strptime(client_time_str, '%Y-%m-%d %H:%M:%S') - timedelta(days = dayDiff)).timestamp()) ##  timedelta(1)
                client_unix_time_prior_end = int((datetime.strptime(client_time_str, '%Y-%m-%d %H:%M:%S') - timedelta(days = (dayDiff -1))).timestamp())

            ##
            objList = None
            if (__info__['matrix'] == 'CdrCall'):
                objList = __collRef__.find({"dateTimeOrigination": {"$gt": client_unix_time}}).sort([("dateTimeOriginationUtc", -1)]).limit(45000)
            elif (__info__['matrix'] == 'CdrCallLast24hr'):
                objList = __collRef__.find({"dateTimeOrigination": {"$gt": last24hr_utc_time}}).sort([("dateTimeOriginationUtc", -1)]).limit(55000)
            elif (__info__['matrix'] == 'CdrCallPrior'):
                yesterday = datetime.now() - timedelta(1)
                unix_time= yesterday.timestamp()
                unix_time_int = int(unix_time)
                logging.debug("unix_time: {0}".format(str(unix_time_int)))
                objList = __collRef__.find({"dateTimeOrigination": {"$lt": client_unix_time_prior_end, "$gt": client_unix_time_prior}}).sort([("dateTimeOrigination", 1)]).limit(45000) 

            response = {}
            cdr_list = []
            for entry in objList:
                ##
                if entry['cmr']: 
                    cdr_list.append({'uid' : entry['uid'],
                        'globalCallID_callManagerId': entry['globalCallID_callManagerId'],
                        'globalCallID_callId': entry['globalCallID_callId'],
                        'dateTimeOrigination': entry['dateTimeOrigination'],
                        'dateTimeOriginationUtc': entry['dateTimeOriginationUtc'],
                        'callingPartyNumber': entry['callingPartyNumber'],
                        'originalCalledPartyNumber': entry['originalCalledPartyNumber'],
                        'finalCalledPartyNumber': entry['finalCalledPartyNumber'],
                        'origDeviceName': entry['origDeviceName'],
                        'destDeviceName': entry['destDeviceName'],
                        'origCallTerminationOnBehalfOf': entry['origCallTerminationOnBehalfOf'],
                        'destCallTerminationOnBehalfOf': entry['destCallTerminationOnBehalfOf'],
                        'duration': entry['duration'],
                        'numberPacketsSent': entry['cmr']['numberPacketsSent'],
                        'numberPacketsReceived': entry['cmr']['numberPacketsReceived'],
                        'numberPacketsLost': entry['cmr']['numberPacketsLost'],
                        'jitter': entry['cmr']['jitter'],
                        'latency': entry['cmr']['latency'],
                        'varVQMetrics': entry['cmr']['varVQMetrics'],
                        'CS': entry['cmr']['CS'],
                        'SCS': entry['cmr']['SCS'],
                        'SCSR': entry['cmr']['SCSR'],
                        'deviceName': entry['cmr']['deviceName']
                        })
                else:
                    cdr_list.append({'uid' : entry['uid'],
                        'globalCallID_callManagerId': entry['globalCallID_callManagerId'],
                        'globalCallID_callId': entry['globalCallID_callId'],
                        'dateTimeOrigination': entry['dateTimeOrigination'],
                        'dateTimeOriginationUtc': entry['dateTimeOriginationUtc'],
                        'callingPartyNumber': entry['callingPartyNumber'],
                        'originalCalledPartyNumber': entry['originalCalledPartyNumber'],
                        'finalCalledPartyNumber': entry['finalCalledPartyNumber'],
                        'origDeviceName': entry['origDeviceName'],
                        'destDeviceName': entry['destDeviceName'],
                        'origCallTerminationOnBehalfOf': entry['origCallTerminationOnBehalfOf'],
                        'destCallTerminationOnBehalfOf': entry['destCallTerminationOnBehalfOf'],
                        'duration': entry['duration']})
            response['cdrs'] = cdr_list
            __return__["status"] = "Success"
            __return__["message"] = "Completed cucm cdr data pulling process"
            __return__["data"] = response
            ## logging.debug("[jchen] return payload: {0}".format(__return__["data"]))
        except Exception as ex:
            __return__["status"] = "Error"
            __return__['message'] = "Error pulling cdr data from Mongodb" + str(ex)
            logging.warning("{0} - {1}".format(__return__["status"],__return__['message']))
        try:
            # Write to DB
            __log__ = {"status": __return__["status"],
                       "primary_action": "API data pulling",
                       "sub_action": "api_cdr_pull",
                       "message": __return__["status"] + " | " + __return__["message"]}
            log_transaction(__log__)
            return (__return__)
        except:
            logging.warning("Error writing to transaction Database")
            logging.warning("-------------------------------------")
            logging.warning("Log - {0}".format(__log__))
            return (__return__)
       

    ## API UCCE Call Pull functions ##
    def api_rtrcall_pull(self,__info__):
        # Standard Return
        __return__ = {}
        try:
            ### Pull all the defautl global information
            logging.debug("api passed in payload: {0}".format(__info__))
            __collRef__ = db.rtrlog
            ##logging.debug("after =>  db.rtrlog ")
            
            ##objList = __collRef__.find().sort({"collection_time": -1}).limit(1)
            objList = __collRef__.find({}).sort("collection_time", -1).limit(1)
            response = {}
            call_list = []
            err_list = []
            for s in objList:
                s['_id'] = str(s['_id'])
                if __info__['matrix'] == 'RtrCall':
                    call_set = s['rcd_data']
                    for entry in call_set:
                        #logging.debug("entry in call data collection: {0}".format(entry))                
                        call_list.append({'_id' : s['_id'],
                                'Time' : entry['Time'],
                                'DN' : entry['DN'],
                                'ANI' : entry['ANI'],
                                'CED' : entry['CED'],
                                'Label' : entry['Label']
                                  })
                    ######  Error list #######
                    err_set = s['error_log']
                    for entry in err_set:
                        err_list.append({'_id' : s['_id'],
                                'Time' : entry['Time'],
                                'Errors' : entry['Errors']
                                  })
            response["calls"] = call_list
            response["errors"] = err_list
            __return__["status"] = "Success"
            __return__["message"] = "Completed ucce call data pulling process"
            __return__["data"] = response
            logging.debug("[jchen] return payload: {0}".format(__return__["data"]))
            #return (__return__)
        except Exception as ex:
            __return__["status"] = "Error"
            __return__['message'] = "Error pulling ucce call data from Mongodb" + str(ex)
            logging.warning("{0} - {1}".format(__return__["status"],__return__['message']))
        try:
            # Write to DB
            __log__ = {"status": __return__["status"],
                       "primary_action": "API data pulling",
                       "sub_action": "api_rtrcall_pull",
                       "message": __return__["status"] + " | " + __return__["message"]}
            log_transaction(__log__)
            return (__return__)
        except:
            logging.warning("Error writing to transaction Database")
            logging.warning("-------------------------------------")
            logging.warning("Log - {0}".format(__log__))
            return (__return__)

    ## api pull tenant service status from SL1 return data to front-end
    def api_svcstatus_pull(self,__info__):
        __return__ = {}
        try:
            logging.debug("api passed in payload: {0}".format(__info__))
            matrix = __info__['matrix']
            __settings_general__ = __db_system__.find_one({'app': 'general'}, {"_id": 0})
            instance = __settings_general__['app_settings']['smb_domain']
            instance = instance.upper()
            svcStatusGrpCore = []
            svcStatusGrpTenant = []
            finesse_active_conn = []
            #core_dict = {
            #   'name': 'Core Infrastructure',
            #    'status': 'Operational',
            #    'events': 'tbd'
            #}
            ## svcStatusGrpCore.append(core_dict)
    
            tenantSvcCollection = db.tenant_svc
            objList = tenantSvcCollection.find({}).sort("collection_time", -1).limit(1)
            for entry in objList:
                core_dict = {
                    'name': 'Webex CCE Customer Administration',
                    'status': entry['core_services']['Webex CCE Customer Administration']['status'],
                    'events': entry['core_services']['Webex CCE Customer Administration']['events']
                }
                svcStatusGrpCore.append(core_dict)

                svc_dict = {
                    'name': 'Voice Service {0}'.format(instance),
                    'status': entry['tenant_services']['Voice Service']['status'],
                    'events': entry['tenant_services']['Voice Service']['events']
                }
                svcStatusGrpTenant.append(svc_dict)
                svc_dict = {
                    'name': 'IVR Service {0}'.format(instance),
                    'status': entry['tenant_services']['IVR Service']['status'],
                    'events': entry['tenant_services']['IVR Service']['events']
                }
                svcStatusGrpTenant.append(svc_dict)
                svc_dict = {
                    'name': 'Contact Center Service {0}'.format(instance),
                    'status': entry['tenant_services']['Contact Center Service']['status'],
                    'events': entry['tenant_services']['Contact Center Service']['events']
                }
                svcStatusGrpTenant.append(svc_dict)
                svc_dict = {
                    'name': 'Reporting Services {0}'.format(instance),
                    'status': entry['tenant_services']['Reporting Services']['status'],
                    'events': entry['tenant_services']['Reporting Services']['events']
                }
                svcStatusGrpTenant.append(svc_dict)
                finesse_active_conn = entry['finesse_active_conn']
            __return__["svcStatusGrpCore"] = svcStatusGrpCore
            __return__["svcStatusGrpTenant"] = svcStatusGrpTenant
            __return__["finesse_active_conn"] = finesse_active_conn
            return __return__
        except Exception as e:
            __return__["svcStatusGrpCore"] = []
            __return__["svcStatusGrpTenant"] = []
            __return__["error"] = "exception happend: {0}".format(str(e))
            return __return__

    
    ## api data push from SL1 for tenant service
    def api_tenant_svc_push(sef,__info__):
        __return__ = {}
        try:
            logging.debug("api_tenant_svc_push => api passed in payload: {0}".format(__info__))
            tenantSvcCollection = db.tenant_svc
            __priorStatus__ = tenantSvcCollection.find_one( {},sort=[( '_id', -1 )])
            __results__ = tenantSvcCollection.insert_one(__info__)

            __settings_general__ = __db_system__.find_one({'app': 'general'}, {"_id": 0})
            tenant = __settings_general__['app_settings']['smb_domain']
            mail_to = __settings_general__['app_settings']['email_to_status_update'].strip()
            ucce_svc_events = __info__['tenant_services']['Contact Center Service']['events']
            #ucce_svc_events = ucce_svc_events.replace("<br/>", "\n")
            msg_body = "Received tenant service status change update from <b>Logvisualizer</b>. <br/><br/>Current Contact Center Service Status: <b>{}</b><br/><b>Events:</b> {}".format(__info__['tenant_services']['Contact Center Service']['status'], ucce_svc_events)
            msg_subject = "Email notification - tenant({}) service status change".format(tenant)
            message = 'To: {}\nSubject: {}\nContent-Type: text/html\n\n{}'.format(mail_to, msg_subject, msg_body)
            email_gateway = __settings_general__['app_settings']['email_gateway']
            sender = __settings_general__['app_settings']['email_from']
            email_to = __settings_general__['app_settings']['email_to_status_update']
            email_to = email_to.strip()
            to_list = email_to.split(",")
            receivers = [s.strip() for s in to_list]
            if __info__['tenant_services']['Contact Center Service']['status'] != __priorStatus__['tenant_services']['Contact Center Service']['status']:
                smtpObj = smtplib.SMTP(email_gateway,25)
                smtpObj.sendmail(sender, receivers, message)

            __return__["status"] = 'OK'
            return __return__
        except Exception as e:
            __return__["status"] = "Exception happend: {0}".format(str(e))
            return __return__



    ## api pull CM device registration status and reason
    def api_cmDevStatus_pull(self,__info__):
        __return__ = {}
        try:
            logging.debug("api passed in payload: {0}".format(__info__))
            mac = __info__['mac']
            __settings_cucm__ = __db_system__.find_one({'app': 'cucm'}, {"_id": 0})
            ip = __settings_cucm__['app_settings']['servers'][0]
            uname = __settings_cucm__['app_settings']['app_usr']
            passwd = __settings_cucm__['app_settings']['app_pwd']
            getDeviceStatusUrl = "https://" + ip + ":8443/realtimeservice2/services/RISService70"
            getDeviceStatusSoap = """<!--RisPort70 API - SelectCmDeviceExt - Request-->
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap="http://schemas.cisco.com/ast/soap">
   <soapenv:Header/>
   <soapenv:Body>
      <soap:selectCmDeviceExt>
         <soap:StateInfo></soap:StateInfo>
         <soap:CmSelectionCriteria>
            <soap:MaxReturnedDevices>10</soap:MaxReturnedDevices>
            <soap:DeviceClass>Any</soap:DeviceClass>
            <soap:Model>255</soap:Model>
            <soap:Status>Any</soap:Status>
            <soap:NodeName></soap:NodeName>
            <soap:SelectBy>Name</soap:SelectBy>
            <soap:SelectItems>
               <!--Zero or more repetitions:-->
               <soap:item>
                  <soap:Item>%s</soap:Item>
               </soap:item>
            </soap:SelectItems>
            <soap:Protocol>Any</soap:Protocol>
            <soap:DownloadStatus>Any</soap:DownloadStatus>
         </soap:CmSelectionCriteria>
      </soap:selectCmDeviceExt>
   </soapenv:Body>
</soapenv:Envelope>""" % (mac)
            ##__settings_general__ = __db_system__.find_one({'app': 'general'}, {"_id": 0})
            response = fun_logging.SendServReq(getDeviceStatusUrl,uname,passwd,getDeviceStatusSoap)
            ##logging.debug('Return from soap request: {0}'.format(str(response)))
            root = ET.fromstring(str(response))
            deviceName = ''
            deviceDirNumber = ''
            deviceDescription = ''
            deviceStatus = ''
            deviceStatusReason = ''
            body = root.find('{http://schemas.xmlsoap.org/soap/envelope/}Body')
            selectCmDeviceResponse = body.find('{http://schemas.cisco.com/ast/soap}selectCmDeviceResponse')
            selectCmDeviceReturn = selectCmDeviceResponse.find('{http://schemas.cisco.com/ast/soap}selectCmDeviceReturn')
            SelectCmDeviceResult = selectCmDeviceReturn.find('{http://schemas.cisco.com/ast/soap}SelectCmDeviceResult')
            CmNodes = SelectCmDeviceResult.find('{http://schemas.cisco.com/ast/soap}CmNodes')
            for itemNode in CmNodes.findall('{http://schemas.cisco.com/ast/soap}item'):
                CmDevices = itemNode.find('{http://schemas.cisco.com/ast/soap}CmDevices')
                if (CmDevices is not None):
                    for item in CmDevices.findall('{http://schemas.cisco.com/ast/soap}item'):
                        device = item.find('{http://schemas.cisco.com/ast/soap}Name')
                        logging.debug(' |--> device: {0}'.format(device.text))
                        deviceName = device.text
                        dirNumber = item.find('{http://schemas.cisco.com/ast/soap}DirNumber')
                        if dirNumber is not None:
                            logging.debug(' |--> dirNumber: {0}'.format(dirNumber.text))
                            deviceDirNumber = dirNumber.text
                        description = item.find('{http://schemas.cisco.com/ast/soap}Description')
                        if description is not None:
                            logging.debug(' |--> description: {0}'.format(description.text))
                            deviceDescription = description.text
                        status  = item.find('{http://schemas.cisco.com/ast/soap}Status')
                        logging.debug(' |--> status: {0}'.format(status.text))
                        deviceStatus = status.text
                        statusReason = item.find('{http://schemas.cisco.com/ast/soap}StatusReason')
                        logging.debug(' |--> statusReason: {0}'.format(statusReason.text))
                        deviceStatusReason = statusReason.text

            logging.debug("Soap msg processing is done ... try to send back result to front-end")
            __return__["deviceName"] = deviceName
            __return__["deviceDirNumber"] = deviceDirNumber
            __return__["deviceDescription"] = deviceDescription
            __return__["deviceStatus"] = deviceStatus
            __return__["deviceStatusReason"] = deviceStatusReason
            __return__["deviceStatusReasonTxt"] = fun_logging.getReasonText(deviceStatusReason)
            logging.debug('Right before return payload..')
            return __return__
        except Exception as e:
            __return__["deviceStatusReasonTxt"] = "exception happend: {0}".format(str(e))
            return __return__

    ## SOAP pull Helper functions
    @staticmethod
    def SendServReq(url,user,passwd,soap):
        headerInfo = {"Connection":"Keep-Alive", "Accept-Encoding":"gzip,deflate", "Content-Type":"text/xml;charset=UTF-8"}
        res = requests.post(url,data=soap,auth=(user, passwd),headers=headerInfo,verify=False).text
        return res

    @staticmethod
    def getReasonText(code):
        mapping = {'0':'Registered','1':'Unknown', '6':'ConnectivityError','8':'DeviceInitiatedReset','9':'CallManagerReset','0':'Registered','1':'Unknown', '6':'ConnectivityError','8':'DeviceInitiatedReset','9':'CallManagerReset',
'10':'DeviceUnregistered','11':'MalformedRegisterMsg','12':'SCCPDeviceThrottling',
'13':'KeepAliveTimeout','14':'ConfigurationMismatch','15':'CallManagerRestart',
'16':'DuplicateRegistration','17':'CallManagerApplyConfig',
'18':'DeviceNoResponse','19':'EMLoginLogout','20':'EMCCLoginLogout',
'25':'RegistrationSequenceError',
'26':'InvalidCapabilities','28':'FallbackInitiated',
'29':'DeviceSwitch','30':'DeviceWipe','31':'DeviceForcedReset',
'33':'LowBattery','34':'ManualPowerOff'}
        if code in mapping:
            return mapping[code]
        else:
            return 'Result not found'


    ## api pull email config
    def api_emailconfig_pull(self, __info__):
        # Standard Return
        __return__ = {}
        try:
            logging.debug("api passed in payload: {0}".format(__info__))
            __settings_general__ = __db_system__.find_one({'app': 'general'}, {"_id": 0})
            email_gateway = __settings_general__['app_settings']['email_gateway']
            email_from = __settings_general__['app_settings']['email_from']
            email_to = __settings_general__['app_settings']['email_to_status_update']
            response = {}
            response["email_gateway"]= email_gateway
            response["email_from"]= email_from
            response["email_to"]= email_to
            __return__["status"] = "Success"
            __return__["message"] = "Completed email config data pulling process"
            __return__["data"] = response
            logging.debug("return payload: {0}".format(__return__["data"]))
            return (__return__)
        except Exception as ex:
            __return__["status"] = "Error"
            __return__['message'] = "Error pulling email config data from Mongodb" + str(ex)
            logging.warning("{0} - {1}".format(__return__["status"],__return__['message']))
            
    ## api save email config
    def api_emailconfig_save(self, __info__):
        # Standard Return
        __return__ = {}
        try:
            logging.debug("api passed in payload: {0}".format(__info__))
            __settings_general__ = __db_system__.find_one({'app': 'general'}, {"_id": 0})
            email_gateway = __info__['email_gateway']
            email_from = __info__['email_from']
            email_to = __info__['email_to']
            __db_system__.update(
                {
                    "app": "general"
                },
                {
                    "$set":{
                        "app_settings.email_gateway": email_gateway,
                        "app_settings.email_from": email_from,
                        "app_settings.email_to_status_update": email_to
                    }
                }
            )

            __return__["status"] = "Success"
            __return__["message"] = "Completed email config data saving process"
            logging.debug("return payload: {0}".format(__return__["message"]))
            return (__return__)
        except Exception as ex:
            __return__["status"] = "Error"
            __return__['message'] = "Error saving email config data from Mongodb" + str(ex)
            logging.warning("{0} - {1}".format(__return__["status"],__return__['message']))

    ## api test email config
    def api_emailconfig_test(self, __info__):
        # Standard Return
        __return__ = {}
        try:
            logging.debug("api passed in payload: {0}".format(__info__))
            __settings_general__ = __db_system__.find_one({'app': 'general'}, {"_id": 0})
            tenant = __settings_general__['app_settings']['smb_domain']
            mail_to = __settings_general__['app_settings']['email_to_status_update'].strip()
            msg_body = "This is an email test from Logvisualizer."
            msg_subject = "Email notification - tenant({}) service status change".format(tenant)
            message = 'To: {}\nSubject: {}\n\n{}'.format(mail_to, msg_subject, msg_body)
            email_gateway = __settings_general__['app_settings']['email_gateway']
            sender = __settings_general__['app_settings']['email_from']
            email_to = __settings_general__['app_settings']['email_to_status_update']
            email_to = email_to.strip()
            to_list = email_to.split(",")
            receivers = [s.strip() for s in to_list]
            smtpObj = smtplib.SMTP(email_gateway,25)
            smtpObj.sendmail(sender, receivers, message)
            __return__["status"] = "Success"
            __return__["message"] = "Completed email config data testing process"
            logging.debug("return payload: {0}".format(__return__["message"]))
            return (__return__)
        except Exception as ex:
            __return__["status"] = "Error"
            __return__['message'] = "Error testing email config data: " + str(ex)
            logging.warning("{0} - {1}".format(__return__["status"],__return__['message']))
    
    ## api pull regions info for Directory Numbers ##
    def api_directory_regions(self):
        __return__ = {}
        try:
            __return__['regions'] = ['North America']
            return (__return__)
        except Exception as ex:
            __return__["status"] = "Error"
            __return__['message'] = "Error retrieving regions data: " + str(ex)
            logging.warning("{0} - {1}".format(__return__["status"],__return__['message']))

    def api_directory_num(self, __info__):
        __return__ = {}
        svc_user = 'svc_dn@wx005.webexcce.com'
        svc_pw = 'Password@123!'
        search_directory = 'OU=directoryNumbers,DC=wx005,DC=webexcce,DC=com'
        ldap_server = 'den01wx005adc01.wx005.webexcce.com'
        logging.debug("api passed in payload: {0}".format(__info__))

        try:
            ## query LDAP for directory numbers
            ldap_client = ldap.initialize('ldap://{0}'.format(ldap_server))
            ldap_client.set_option(ldap.OPT_REFERRALS, 0)
            ldap_client.simple_bind_s(svc_user, svc_pw)
            logging.debug("LDAP credentials were good!")
            searchattrlist = ['cn','telephoneNumber','mobile','name']
            searchfilter = 'objectClass=contact'
            ldap_result_id  = ldap_client.search(search_directory, ldap.SCOPE_SUBTREE, searchfilter, searchattrlist)
            result_set = []
            while 1:
                result_type, result_data = ldap_client.result(ldap_result_id, 0)
                if (result_data == []):
                    break
                else:
                    if result_type == ldap.RES_SEARCH_ENTRY:
                        result_set.append(result_data)
            dnObjs = []
            for row in result_set:
            ## [('CN=7193093853,OU=directoryNumbers,DC=wx005,DC=webexcce,DC=com', {'cn': [b'7193093853'], 'telephoneNumber': [b'7193093853'], 'name': [b'7193093853']})]
                #logging.debug("entry in Array: {0}".format(row))
                item = row[0]
                name = item[0]
                #logging.debug("name: {0}".format(name))
                dict = item[1]
                #logging.debug("dict: {0}".format(dict))
                entry = {}
                entry['name'] = name
                if ('telephoneNumber' in dict):
                   entry['phone'] = dict['telephoneNumber'][0].decode("utf-8")
                if ('mobile' in dict):
                   entry['mobile'] =  dict['mobile'][0].decode("utf-8")
                dnObjs.append(entry)
            __return__['dnObjects'] = dnObjs
            return (__return__)
        except Exception as ex:
            ldap_client.unbind()
            __return__["status"] = "Error"
            __return__['message'] = "Error pulling Directory number data: " + str(ex)
            logging.warning("{0} - {1}".format(__return__["status"],__return__['message']))
            return (__return__)


    def api_directory_num_save(self, __info__):
        __return__ = {}
        svc_user = 'svc_dn@wx005.webexcce.com'
        svc_pw = 'Password@123!'
        search_directory = 'OU=directoryNumbers,DC=wx005,DC=webexcce,DC=com'
        ldap_server = 'den01wx005adc01.wx005.webexcce.com'
        logging.debug("[api_directory_num_save] api passed in payload: {0}".format(__info__))
        cn = __info__['cn'].strip()
        phone = __info__['phone'].strip()
        mobile = __info__['mobile'].strip()

        try:
            ## query LDAP for directory numbers
            ldap_client = ldap.initialize('ldap://{0}'.format(ldap_server))
            ldap_client.set_option(ldap.OPT_REFERRALS, 0)
            ldap_client.simple_bind_s(svc_user, svc_pw)
            logging.debug("LDAP credentials were good!")
            if (phone != ''):
                mod_attrs = [( ldap.MOD_REPLACE, "telephoneNumber", phone.encode('ascii'))]
                ldap_client.modify_s(cn, mod_attrs)
                logging.debug("Directory Entry:  telephoneNumber updated")

            if (mobile != ''):
                mod_attrs = [( ldap.MOD_REPLACE, "mobile", mobile.encode('ascii'))]
                ldap_client.modify_s(cn, mod_attrs)
                logging.debug("Directory Entry:  mobile Number updated")
            
            if (mobile == ''):
                mod_attrs = [( ldap.MOD_DELETE, "mobile", None)]
                ldap_client.modify_s(cn, mod_attrs)
                logging.debug("Directory Entry:  mobile Number deleted")
            
            if (phone == ''):
                mod_attrs = [( ldap.MOD_DELETE, "telephoneNumber", None)]
                ldap_client.modify_s(cn, mod_attrs)
                logging.debug("Directory Entry:  phone Number deleted")

            __return__['status'] = 'Ok'
            return (__return__)
        except Exception as ex:
            __return__["status"] = "Error"
            __return__['message'] = "Error saving directory number: " + str(ex)
            logging.warning("{0} - {1}".format(__return__["status"],__return__['message']))
            ldap_client.unbind()
            return (__return__)


    ## api pull logs for specfic outage scenario
    def api_loggingExpress_pull(self,__info__):
        # Standard Return
        __return__ = {}
        try:
            tic = time.time()    ## start timeer
            logging.debug("api passed in payload: {0}".format(__info__))
            __settings_general__ = __db_system__.find_one({'app': 'general'}, {"_id": 0})
            case_dir = __settings_general__['app_settings']['web_share_dir'] + 'express/tmp/'
            bundle_dir = __settings_general__['app_settings']['web_share_dir'] + 'express/'
            fun_logging.ensure_dir(self, bundle_dir)
            fun_logging.ensure_dir(self, case_dir) 
            ##   ==> /var/logvisualizer/dist/log_file_respository/express/
            fun_logging.ensure_dir(self, case_dir)
            ### PUll all default information for all the selected Applications
            ## Dropped call - Pull CUCM, VVB, CVP, PG-PIM logs
            ## Agent Logout - Pull Finesse, ICM-CTI, JTAPI, CUCM CTI, CUCM Call Manager
            __app_split__ = []
            if __info__['log_option'] == 'DroppedCall':
                __app_split__ = ['cucm','vvb','cvp','cvpvxml','pg']
            elif __info__['log_option'] == 'AgentLoggout':
                __app_split__ = ['fin','cucm','pg']
            __settings_applications__ = {}
            for __applications__ in __app_split__:
                logging.debug("Express - PUll {0} from DB".format(__applications__))
                __items_list__ = __db_system__.find_one({'app': __applications__.lower()}, {"_id": 0})
                logging.debug("Express - PUlled {0} from DB".format(__items_list__))
                logging.debug("Express - Count is greater then 1")
                __settings_applications__[__applications__] = __items_list__
                logging.debug("Express - Servers for {0}".format(__applications__))
                logging.debug("Express - Are {0}".format(__settings_applications__[__applications__]['app_settings']['servers']))

            time_offset_val = '60'  ## set to last 60 minutes log by now
            with ThreadPoolExecutor(max_workers=100) as executor:
                for __application_types__ in __settings_applications__:
                    logging.debug("Express - Start Pulling {0} Threads".format(__application_types__))
                    ## step 1 -  remove all logs
                    out_file =  case_dir + '/'  + __application_types__  + '-' + time_offset_val + '.tar'
                    src_dir = __settings_general__['app_settings']['sftp_upload_dir'] + __settings_applications__[__application_types__]['app_settings']['sftp_directory']
                    remove_dir = __settings_general__['app_settings']['sftp_instant_dir']
                    ## step 2 -  start log collection thread
                    executor.submit(fun_logging.__fun_logging_pull(self, __settings_general__['app_settings'], __settings_applications__[__application_types__]['app_settings'], time_offset_val, __application_types__, out_file, src_dir, remove_dir))
            ### Finally bundle all files to one tar ball - xxxx.tar under case dir ###
            ## extract tar in case_dir
            for root, dirs, files in os.walk(case_dir):
                for name in files:
                    if ('.tar' in name):
                        logging.debug("tar file name: {0}".format(name))
                        log_tar = tarfile.open(case_dir + name)
                        log_tar.extractall(case_dir) # specify which folder to extract to
                        log_tar.close()
                        if os.path.exists(case_dir + name):
                            os.remove(case_dir + name) # remove tar file at the end

            fun_logging.make_tarfile(bundle_dir + '/' +  __info__['log_option'] + '.tar', case_dir)
            fun_logging.remove_logs(bundle_dir, 'tmp') ## clean up individual tars in tmp folder after final bundle

            logging.debug("Total time for functions = {0}".format(time.time() - tic))
            ### END ###
            __return__["status"] = "Success"
            __return__["message"] = "Completed log pulling for outage - {0}".format(__info__['log_option'])
            return (__return__)
        except Exception as ex:
            __return__["status"] = "Error"
            __return__["message"] = "Error pulling app log for outage: " + str(ex)
            logging.warning("{0} - {1}".format(__return__["status"],__return__['message']))
            return (__return__)

    ## API call from remote SL1 system - log collection request for SNOW case
    def api_log_push(self,__info__):
        try:
            logging.debug("SL1 - api passed in payload: {0}".format(__info__))

            ### collect application logs and put under case directory ###
            ##
            ### Pull all the defautl global information
            __settings_general__ = __db_system__.find_one({'app': 'general'}, {"_id": 0})
            case_dir = __settings_general__['app_settings']['web_share_dir'] + 'SNOW/' +  __info__['snow_instance'] + '/' +  __info__['case']                                              ## /data/SNOW/  ==> /var/logvisualizer/dist/log_file_respository/SNOW/
            fun_logging.ensure_dir(self, __settings_general__['app_settings']['web_share_dir'] + 'SNOW')
            fun_logging.ensure_dir(self, case_dir)
            ### PUll all default information for all the selected Applications 
            __app_split__ = __info__['applications'].split(",")
            __settings_applications__ = {}
            for __applications__ in __app_split__:
                logging.debug("SL1 - PUll {0} from DB".format(__applications__))
                __items_list__ = __db_system__.find_one({'app': __applications__.lower()}, {"_id": 0})
                logging.debug("SL1 - PUlled {0} from DB".format(__items_list__))
                logging.debug("SL1 - Count is greater then 1")
                __settings_applications__[__applications__] = __items_list__
                logging.debug("SL1 - Servers for {0}".format(__applications__))
                logging.debug("SL1 - Are {0}".format(__settings_applications__[__applications__]['app_settings']['servers']))
            
            time_offset_val = '30'  ## set to last 30 minutes log by now
            with ThreadPoolExecutor(max_workers=100) as executor:
                for __application_types__ in __settings_applications__:
                    logging.debug("SL1 - Start Pulling {0} Threads".format(__application_types__))
                    ## step 1 -  remove all logs
                    out_file =  case_dir + '/'  + __application_types__  + '-' + time_offset_val + '.tar'
                    src_dir = __settings_general__['app_settings']['sftp_upload_dir'] + __settings_applications__[__application_types__]['app_settings']['sftp_directory']
                    remove_dir = __settings_general__['app_settings']['sftp_instant_dir'] 
                    ## step 2 -  start log collection thread
                    executor.submit(fun_logging.__fun_logging_pull(self, __settings_general__['app_settings'], __settings_applications__[__application_types__]['app_settings'], time_offset_val, __application_types__, out_file, src_dir, remove_dir))
            ### Finally bundle all files to one tar ball - casexxxx.tar under case dir ###
            fun_logging.make_tarfile(case_dir + '/' +  __info__['case'] + '.tar', case_dir)
        except Exception as ex:
            logging.warning("SL1 - Error during api_log_push call .. " + str(ex))
