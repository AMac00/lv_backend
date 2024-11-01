import os, time, urllib


class BaseConfig:
    #### TESTING ####
    DEBUGGING = 1
    LOGGING_FILE = '{0}.log'.format(time.strftime("%m-%d-%Y_%H"))
    #### VVB ####
    VVB_SERVERS = ["10.38.228.14"]
    #### CUCM ####
    CUCM_SERVERS = ["10.38.228.28"]
    #### FINESSE ####
    FIN_SERVERS = ["10.1.34.11"]
    #### CVP VXML ####
    CVPVXML_SERVERS = ['10.1.34.7']
    #### SFTP SERVER IP ####
    SFTP_SERVER = "10.38.225.61"
    SFTP_INSTANT_DIR = "/data/loguser/upload/instant/"
    SFTP_UPLOAD_DIR = "/data/loguser/upload/"
    ##### WEB LOG SHARE ####
    WEB_SHARE_DIR = "/var/logvisualizer/dist/log_file_respository/"
    #### LDAP ####
    USE_LDAP_LOGIN = True 
    LDAP_SERVER = "10.38.225.10"
    LDAP_DOMAIN = "lab.local"
    BASE_DN = "DC=lab,DC=local"
    #### CVP Vxml ####
    SMB_SHARE_NAME = 'VXMLServer'
    SMB_APP_TOP_LEVEL = '/applications/'
    SMB_PORT = 445
    SMB_DOMAIN = 'lab'
    #### Log time between start and stop timers ####
    LOG_TIME_SPAN = "6000"