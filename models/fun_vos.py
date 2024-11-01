import requests, urllib3, ssl
from urllib3.exceptions import HTTPError as BaseHTTPError
from requests.auth import HTTPBasicAuth
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
# Threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from logging.handlers import RotatingFileHandler
# Import becasue logs are available via API
import paramiko
from paramiko_expect import SSHClientInteraction
import time
import traceback

from smb.SMBConnection import SMBConnection
from socket import gethostbyname
import socket
import os

from env_config import ProductionConfig


# Version 1 of the VVB pulls



class fun_vos():

    def __init__(self):
        return

    def __version__(self):
        __version__ = 0.2
        return(__version__)

    # This is the AXL pull request for pulling file from VOSS instances
    def __vos_request__(self,__session__,__url__, __headers__, __payload__):
        ''' Threaded function for pulls'''
        try:
            __method__ = "POST"
            logging.debug("URL = {0}".format(__url__))
            logging.debug(("{0} Payload is {1}".format(__method__,__payload__)))
            __response__ = __session__.request(__method__, __url__, headers=__headers__, data=__payload__, verify=False)
            logging.debug("Return Status Code = {0}".format(__response__.status_code))
            logging.debug("Return Message = {0}".format(__response__.text))
            if __response__.status_code == 200:
                logging.debug("Test1 = {0}".format(__response__.status_code))
                __body__ = BeautifulSoup(__response__.text, 'xml')
                logging.debug("Test2 = {0}".format(__body__))
                __items__ = __body__.find('SetOfFiles')
                if not __items__:
                    logging.warning("Didn't find any files to download, you might increase the timer.")
                    return()
                logging.debug("Test3 = {0}".format(__items__))
                for __item__ in __items__.find_all('item'):
                    try:
                        logging.info("File = {0} Size= {1}".format(__item__.find('name').contents[0],
                                                            __item__.find('filesize').contents[0]))
                    except:
                        pass
            elif __response__.status_code == 500:
                __body__ = BeautifulSoup(__response__.text, 'xml')
                __faultstring__ = __body__.find("faultstring")
                logging.error("Error - {0}".format(__faultstring__.contents[0]))
            else:
                logging.error("Non standard request response = {0}".format(__response__.status_code))
        except requests.exceptions.HTTPError as errh:
            logging.error("Http Error:", errh)
        except requests.exceptions.ConnectionError as errc:
            logging.error("Error Connecting:", errc)
        except requests.exceptions.Timeout as errt:
            logging.error("Timeout Error:", errt)
        except requests.exceptions.RequestException as err:
            logging.error("OOps: Something Else", err)

    # # This is temp until the speechserver logs are available via API
    def __vos_ssh__(self,__vos_server__,__logtypes__,__info__):
        # Use SSH client to login
        try:
            # Create a new SSH client object
            logging.debug("TEST!")
            client = paramiko.SSHClient()
            # Set SSH key parameters to auto accept unknown hosts
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            logging.debug("Trying to connect to = {0}".format(__vos_server__))
            # Connect to the host
            client.connect(hostname=__vos_server__, username=__info__["os_usr"], password=__info__["os_pwd"])
            __prompt__ = "admin:"
            logging.debug("[jc] Connected to = {0}".format(__vos_server__))
            # Create a client interaction class which will interact with the host
            with SSHClientInteraction(client, timeout=10, display=False) as interact:
                logging.debug("[jc] inside sshclientInteraction ..")
                interact.expect(__prompt__, timeout=15)
                __log_file__ = 'file get activelog {0} reltime minutes {1}'.format(__info__['log_ssh'][__logtypes__], __info__['time_offset'])
                logging.debug("file active = {0}".format(__log_file__))
                #interact.send('file get activelog /uccx/log/MIVR/* reltime minutes 60')
                interact.send(__log_file__)
                time.sleep(2)
                logging.debug("Waiting of y/no")
                interact.send("y")
                logging.debug("Sent {0}".format('Y'))
                interact.send(__info__["sftpserver"])
                logging.debug("Sent {0}".format(__info__["sftpserver"]))
                interact.send(__info__["sftport"])
                logging.debug("Sent {0}".format(__info__["sftport"]))
                interact.send(__info__["sftpuser"])
                logging.debug("Sent {0}".format(__info__["sftpuser"]))
                interact.send(__info__["sftppwd"])
                logging.debug("Sent {0}".format(__info__["sftppwd"]))
                interact.send(__info__["sftpdirectory"])
                logging.debug("Sent {0}".format(__info__["sftpdirectory"]))
                interact.send("yes")
                interact.expect(__prompt__)
                __output__ = interact.current_output
                if "o files matched filter criteria" in __output__:
                    logging.error("{0} on {1} did NOT contain any files".format(__info__['log_type'],__vos_server__))
                logging.debug("SSH output for {0} = {1}".format(__vos_server__,__output__))
                interact.send('exit')
                interact.expect()
        except Exception:
            #traceback.print_exc()
            logging.error("Error getting {0} from {1} via ssh = traceback = {2}".format(__info__["log_type"],__vos_server__,traceback.print_exc()))
        finally:
            try:
                client.close()
            except Exception:
                logging.error("Error closing {0} ssh connection".format(__vos_server__))
                pass

    #### Helper functions ####

    def getDurationInHours(self, sec):
        hours = divmod(sec, 3600)[0]
        return int(hours)


    def ensure_dir(self, file_path):
        ##directory = os.path.dirname(file_path)
        try:
            if not os.path.exists(file_path):
                os.makedirs(file_path)
        except Exception as e:
            logging.error('Exception' + str(e))

    def collect_cvpvxml_log(self, server_ip, __info__):
        username = __info__['os_usr'] 
        password = __info__['os_pwd']
        domain = ProductionConfig.SMB_DOMAIN           ## 'lab'
        port = ProductionConfig.SMB_PORT               ## 445
        share_name = ProductionConfig.SMB_SHARE_NAME   ## 'VXMLServer'
        toplevel = ProductionConfig.SMB_APP_TOP_LEVEL  ## '/applications/'
        appArr = []
        logTypes = []
        sftpBasedDir = ProductionConfig.SFTP_INSTANT_DIR + __info__['app'] + '/'  ##  '/data/loguser/upload/instant/cvpvxml/'
        logTimeThresholdInHr = 2900  ## 24 hour in production

        logTypeDict = __info__['log_smb']
        for key in logTypeDict:
            logTypes.append(logTypeDict[key])
        
        ##logging.debug(username + '|' + password + '|' + domain + '|' +str(port) + '|' + share_name + '|' + toplevel + '|' + sftpBasedDir)

        try:
            conn = SMBConnection(username, password, socket.gethostname(), server_ip, domain, is_direct_tcp=True)
            assert conn.connect(server_ip, port)
            ##logging.debug('[jc] after making smb connection ...')
	
            shares = conn.listShares()

            for share in shares:
                if (share.name == share_name):
                    sharedfiles = conn.listPath(share.name, toplevel)
                    for sharedfile in sharedfiles:
                        if (sharedfile.filename != '.' and sharedfile.filename != '..'):
                            appArr.append(sharedfile.filename)
                            ##logging.debug('[jc] after making smb connection ...' + sharedfile.filename)

            ### Create directory is not existed ###
            ##logging.debug('create dir => ' + sftpBasedDir + server_ip)
            fun_vos.ensure_dir(self, sftpBasedDir + server_ip)

            now = datetime.now()
            dt_str = now.strftime('%Y-%m-%d %H:%M:%S')

            for logtype in logTypes:
                for app in appArr:
                    ##ensure_dir(sftpBasedDir + server_ip + '/' + app)
                    logDir = '/applications/' + app + '/logs/' + logtype + '/'
                    ##logging.debug('logDir => ' + logDir)
                    for share in shares:
                        if (share.name == share_name):
                            sharedfiles = conn.listPath(share.name, logDir)
                            for sharedfile in sharedfiles:
                                if (sharedfile.filename != '.' and sharedfile.filename != '..'):
                                    if (fun_vos.getDurationInHours(self, (now - datetime.fromtimestamp(sharedfile.last_write_time)).total_seconds()) < logTimeThresholdInHr):
                                        ##logging.debug('converted time in utc: ' + sharedfile.filename + ' | '  + datetime.fromtimestamp(sharedfile.last_write_time).strftime('%Y-%m-%d %H:%M:%S'))
                                        dirDownload = sftpBasedDir + server_ip + '/' + app + '/' + logtype
                                        ##logging.debug('create app dir => ' + sftpBasedDir + server_ip + '/' + app)
                                        ##logging.debug('create download dir => ' +  dirDownload)
                                        fun_vos.ensure_dir(self, sftpBasedDir + server_ip + '/' + app)
                                        fun_vos.ensure_dir(self, dirDownload)
                                        fileDownload =  dirDownload + '/' + sharedfile.filename
                                        with open(fileDownload, 'wb') as file_obj:
                                            conn.retrieveFile(share_name, logDir + sharedfile.filename, file_obj)


            conn.close()
        except Exception as ex:
            logging.error('Exception: ' + str(ex))


    ##### END #####


    def __vos_x_min_log_pull__(self, __info__):
        '''
        This function pulls X minutes from the current system time from VVB
        '''
        # Validate input
        try:
            __err_list__ = []
            __var_require__ = ["ServiceLogs", "time_offset", "sftpserver", "sftport", "sftpuser", "sftpdirectory","app_srv", "app_usr", "app_pwd"]
            for __var__ in __var_require__:
                if __var__ not in __info__:
                    __err_list__.append(__var__)
            if len(__err_list__) > 0:
                logging.error("Misssing input information for __vos_x_min_log_pull__ = {0}".format(__err_list__))
                return()
        except:
            logging.error("Error with function input")
            return()
        # Pull Current Time and Build AXL Request Body
        ''' Inconsistent pulls - Check date time '''
        try:
            if 'http' in __info__["log_connection"]:
                ''' Build Concatenate servicelog pulls '''
                __servicelog_items__ = ""
                for __servicelogs__ in __info__["ServiceLogs"]:
                    __servicelog_items__ = __servicelog_items__ + '<item xsi:type=\"xsd:string\">{0}</item>\r\n'.format(__servicelogs__)
                logging.debug(__servicelog_items__)
                ''' Build current working time '''
                __date_1__ = datetime.now()
                __to_time__ = ('<ToDate xsi:type=\"xsd:string\">{0}</ToDate>\r\n'.format(__date_1__.strftime("%m/%d/%Y %H:%M %p")))
                __date_2__=  __date_1__ - timedelta(minutes=int(__info__['time_offset']))
                logging.debug("{0} = {1}".format("__date_1__",__date_1__))
                __from_time__ = ('<FromDate xsi:type=\"xsd:string\">{0}</FromDate>\r\n'.format(__date_2__.strftime("%m/%d/%Y %H:%M %p")))
                logging.debug("{0} = {1}".format("__date_2__", __date_2__))
                ''' Build sftp Information '''
                __sftp_timezone_ = ("{0}".format("(GMT-6:0) America/Chicago"))
                __sftp_port__ = ('<Port xsi:type=\"xsd:byte\">{0}</Port>\r\n '.format(__info__['sftport']))
                __sftp_server__ = ('<IPAddress xsi:type=\"xsd:string\">{0}</IPAddress>\r\n'.format(__info__['sftpserver']))
                __sftp_user__ = ('<UserName xsi:type=\"xsd:string\">{0}</UserName>\r\n'.format(__info__['sftpuser']))
                __sftp_pwd__ = ('<Password xsi:type=\"xsd:string\">{0}</Password>\r\n  '.format(__info__['sftppwd']))
                __sftp_zip__ = ('<ZipInfo xsi:type=\"xsd:boolean\">{0}</ZipInfo>\r\n'.format("false"))
                __sftp_dir__ = ('<RemoteFolder xsi:type=\"xsd:string\">{0}</RemoteFolder>\r\n'.format(__info__['sftpdirectory']))
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
                __session__.auth = HTTPBasicAuth(__info__["app_usr"], __info__["app_pwd"])
                ''' Build URL and Send Request'''
                with ThreadPoolExecutor(max_workers=100) as executor:
                    for __vos_servers__ in __info__["app_srv"]:
                        __url__ = ('https://{0}:8443/logcollectionservice/services/LogCollectionPort'.format(__vos_servers__))
                        executor.submit(fun_vos.__vos_request__(self,__session__,__url__, __headers__, __payload__))
        except:
            logging.error("{0} AXL is broken.. You might want to fix it.".format("__vvb_x_min_log_pull"))
            return
        # PUll directly from SSH ( required for VVB ) - short term until they fix it.
        try:
            if 'ssh' in __info__["log_connection"]:
                with ThreadPoolExecutor(max_workers=100) as executor:
                    for __vos_server__ in __info__["app_srv"]:
                        for __logtypes__ in __info__["log_ssh"]:
                            executor.submit(fun_vos.__vos_ssh__(self,__vos_server__,__logtypes__,__info__))
        except:
            logging.error("{0}:{1} SSH is broken.. You might want to fix it.".format(__vos_server__,"__vvb_x_min_log_pull"))
            return
        
        # PULL logs from smb share (required for CVP Vxml logs(
        try:
            if 'smb' in __info__["log_connection"]:
                for __cvpvxml_server__ in __info__["app_srv"]: 
                    ##logging.debug("[jc][fun_vos] " + __cvpvxml_server__)
                    fun_vos.collect_cvpvxml_log(self,__cvpvxml_server__, __info__)

 
        except Exception as ex:
            logging.error("Exception: " + str(ex))
            logging.error("{0}:{1} SMB is broken.. You might want to fix it.".format(__cvpvxml_server__,"__vos_x_min_log_pull"))
            return


        return()
