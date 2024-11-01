from pymongo import MongoClient
import urllib

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
systemdb = lvdb['system']
tenantsvcdb = lvdb['tenant_svc']

__action__ = "__drop_collection__ __seed_db__  __deleteTenantSvc_collection__"

if "__deleteTenantSvc_collection__" in __action__:
    tenantsvcdb.delete_many({})

if "__drop_collection__" in __action__:
    systemdb.drop()

if "__seed_db__"  in __action__:
    __seed_info__ = [{"app" : 'general',
                      'app_settings': {
                      'offset_time': '60',
                      'log_age': '86400',
                      'sftp_server': '104.156.47.12',
                      'sftp_port': '22',
                      'sftp_usr':"loguser", 
                      'sftp_pwd':'password@123', 
                      'sftp_instant_dir':'/data/loguser/upload/instant/',
                      'sftp_upload_dir':'/data/loguser/upload/', 
                      'web_share_dir':'/var/logvisualizer/dist/log_file_respository/', 
                      'ldap_use':True, 
                      'ldap_server':'den01mgmtadc01.mgmt.webexcce.com',
                      'ldap_domain':'mgmt.webexcce.com',
                      'ldap_base_dn':'DC=mgmt,DC=webexcce,DC=com',
                      'sso_use':False, 
                      'sso_idpentryurl':'https://sso.wx025.webexcce.com/adfs/ls/idpinitiatedsignon',
                      'sso_homeRealmSelection':'http://sso.wx025.webexcce.com/adfs/services/trust',
                      'sso_domain':'wx025',
                      'email_gateway':'smtp-den01.mgmt.webexcce.com',
                      'email_from':'monitoring@mgmt.webexcce.com',
                      'email_to_status_update':'jianxin.chen@ttec.com',
                      'smb_share_name':'CVP', 
                      'smb_app_top_level':'/VXMLServer/applications/',
                      'smb_port':445, 
                      'smb_domain':'wx025'
                      }},
            {"app": "cucm",
                'app_settings': {
                'app_usr': 'ccmadmin',
                'app_pwd': 'HCScucm123!',
                'os_usr': 'administrator',
                'os_pwd': 'HCScucm123',
                'log_connection': 'ssh',
                'log_ssh': {'SLD':'/cm/trace/ccm/sdl/*.gz*','CALLLOG':'/cm/trace/ccm/calllogs/*.gz*'},
                'log_http': ['Cisco CallManager','Cisco CTIManager'],
                'log_type': {'MIVR': "/uccx/log/MIVR/*", 'MCVD': "/uccx/log/MCVD/*"},
                'sftp_directory': 'instant/cucm',
                'servers': ['104.156.46.16','104.156.46.17','104.156.47.17']
                }},
             {"app": 'vvb',
                'app_settings': {
                'app_usr': 'vvbadmin',
                'app_pwd': 'HCSvvb123!',
                'os_usr': 'administrator',
                'os_pwd': 'HCSvvb123',
                'log_connection': 'ssh',
                'log_ssh': {'MIVR':"/uccx/log/MIVR/*", 'SpeechServer':"speechserver/logs/SpeechServer/*", 'MCVD': "/uccx/log/MCVD/*"}, 
                'log_http': ['temp'],
                'sftp_directory': 'instant/vvb',
                'servers': ['104.156.46.138','104.156.47.138']
            }},
            {"app": 'unity',
                'app_settings': {
                'app_usr': 'cucadmin',
                'app_pwd': 'HCScuc123!',
                'os_usr': 'administrator',
                'os_pwd': 'HCScuc123',
                'log_connection': 'ssh',
                'log_ssh': {'TOMCAT':"/cuc/diag_Tomcat_*.uc", 'CUCSMGR':"/cuc/diag_CuCsMgr_*.uc"},
                'log_http': ['temp'],
                'sftp_directory': 'instant/unity',
                'servers': ['104.156.46.19','104.156.47.19','104.156.46.113']
            }},
            {"app": 'cvpvxml',
                'app_settings': {
                'app_usr': 'tbd',
                'app_pwd': 'tdb',
                'os_usr': 'svc_smb',
                'os_pwd': '9v7khMd7v#KKhMZN#pUe',
                'log_connection': 'smb',
                'log_smb': {'Activity':"ActivityLog", 'Error': "ErrorLog"},
                'log_http': ['temp'],
                'sftp_directory': 'instant/cvpvxml',
                'servers': ['104.156.46.8','104.156.47.8','104.156.46.29','104.156.47.29']
            }},
            {"app": 'cvp',
                'app_settings': {
                'app_usr': 'tbd',
                'app_pwd': 'tdb',
                'os_usr': 'svc_smb',
                'os_pwd': '9v7khMd7v#KKhMZN#pUe',
                'log_connection': 'smb',
                'log_smb': {'CVP':"CVP.", 'Error': "Error."},
                'log_http': ['temp'],
                'sftp_directory': 'instant/cvp',
                'servers': ['104.156.46.8','104.156.47.8','104.156.46.29','104.156.47.29']
            }},
            {"app": "fin",
             'app_settings': {
                'app_usr': 'finadmin',
                'app_pwd': 'HCSfin123!',
                'os_usr': 'administrator',
                'os_pwd': 'HCSfin123',
                'log_connection': 'ssh',
                'log_ssh': {'clientlogs': "/desktop/logs/clientlogs/*",'valvelogs':"/desktop/logs/valve"},
                'log_http': ['temp'],
                'sftp_directory': 'instant/fin',
                'servers': ['104.156.46.13','104.156.47.13']
            }},
            {"app": "clc",
             'app_settings': {
                'app_usr': 'clcadmin',
                'app_pwd': 'HCSclc123!',
                'os_usr': 'administrator',
                'os_pwd': 'HCSclc123',
                'log_connection': 'ssh',
                'log_ssh': {'clclogs': "/hybrid/log/cloudconnectmgmt recurs"},
                'log_http': ['temp'],
                'sftp_directory': 'instant/clc',
                'servers': ['104.156.46.15','104.156.47.15']
            }},
            {"app": "livedata",
             'app_settings': {
                'app_usr': 'cuicadmin',
                'app_pwd': 'HCScuic123!',
                'os_usr': 'administrator',
                'os_pwd': 'HCScuic123',
                'log_connection': 'ssh',
                'log_ssh': {'livedatalogs': "livedata/logs/*/*"},
                'log_http': ['temp'],
                'sftp_directory': 'instant/livedata',
                'servers': ['104.156.46.14','104.156.47.14']
            }},
            {"app": 'rtr',
                'app_settings': {
                'app_usr': 'admin',
                'app_pwd': '.o0ECS0o.',
                'os_usr': 'svc_smb',
                'os_pwd': '9v7khMd7v#KKhMZN#pUe',
                'log_connection': 'porticoRTR',
                'log_portico': {'RtrLog':'rtr', 'AgiLog':'agi'},
                'log_http': ['temp'],
                'sftp_directory': 'instant/rtr',
                'servers': ['104.156.46.5','104.156.47.5']
            }},
            {"app": 'pg',
                'app_settings': {
                'app_usr': 'admin',
                'app_pwd': '.o0ECS0o.',
                'os_usr': 'svc_smb',
                'os_pwd': '9v7khMd7v#KKhMZN#pUe',
                'log_connection': 'porticoPG',
                'log_portico': {'CtiLog':'ctisvr', 'PgLog':'jgw1', 'VruLog':'pim1'},
                'log_http': ['temp'],
                'sftp_directory': 'instant/pg',
                'servers': ['104.156.46.7','104.156.47.7']
            }}]
    x = systemdb.insert_many(__seed_info__)
    print("{0}".format(x))

if "__get_info__" in __action__:
    # __db_system__ = systemdb.find({'tags': { '$in': ['general']}})
    __db_system__ = systemdb.find({'app': 'cvpvxml'}, {"_id": 0})
    for doc in __db_system__:
        print("{0}".format(doc))

