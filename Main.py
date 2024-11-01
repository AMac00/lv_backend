# Model / Function Imports
from models.fun_vos import fun_vos
from models.fun_filemanagement import fun_file_management
import logging, time, os
from logging.handlers import RotatingFileHandler
from concurrent.futures import ThreadPoolExecutor
from env_config import ProductionConfig

''' Static variables for POC - Migrate to DB'''
__vvb_info__ = {'ServiceLogs': ['Cisco Unified CCX Engine'],
            'app': 'vvb',
            'app_log_age': ProductionConfig.LOG_AGE,
            'time_offset': ProductionConfig.LOG_TIME_SPAN,
            'app_srv': ProductionConfig.VVB_SERVERS,
            'app_usr': 'admin',
            'app_pwd': '.o0ECS0o.',
            'os_usr': 'admin',
            'os_pwd': '.o0ECS0o.',
            'log_type': {'MIVR':"/uccx/log/MIVR/*", 'MCVD': "/uccx/log/MCVD/*"},
            'log_connection': 'ssh ',
            'sftpserver': ProductionConfig.SFTP_SERVER,
            'sftport': '22',
            'sftpuser': 'loguser',
            'sftppwd': 'password@123',
            'sftpdirectory': 'vvb'}

__ccm_info__ = {'ServiceLogs': ['Cisco CallManager','Cisco CTIManager'],
            'app': 'ccm',
            'app_log_age': ProductionConfig.LOG_AGE,
            'time_offset': ProductionConfig.LOG_TIME_SPAN,
            'app_srv': ProductionConfig.CUCM_SERVERS,
            'app_usr': 'admin',
            'app_pwd': '.o0ECS0o.',
            'os_usr': 'admin',
            'os_pwd': '.o0ECS0o.',
            'log_type': {'MIVR': "/uccx/log/MIVR/*", 'MCVD': "/uccx/log/MCVD/*"},
            'log_connection': 'http',
            'sftpserver': ProductionConfig.SFTP_SERVER,
            'sftport': '22',
            'sftpuser': 'loguser',
            'sftppwd': 'password@123',
            'sftpdirectory': 'cucm'}

__fin_info__ = {'ServiceLogs': ['Finesse'],
            'app': 'fin',
            'app_log_age': ProductionConfig.LOG_AGE,
            'time_offset': ProductionConfig.LOG_TIME_SPAN,
            'app_srv': ProductionConfig.FIN_SERVERS,
            'app_usr': 'finadmin',
            'app_pwd': '.o0ECS0o.',
            'os_usr': 'administrator',
            'os_pwd': 'HCSfin123',
            'log_type': {'clientlogs': "/desktop/logs/clientlogs/*"},
            'log_connection': 'ssh',
            'sftpserver': ProductionConfig.SFTP_SERVER,
            'sftport': '22',
            'sftpuser': 'loguser',
            'sftppwd': 'password@123',
            'sftpdirectory': 'fin'}

try:
    # Need because the cron job looks for the local user directory
    #__cwd__ = "/var/logger/logs"
    '''  Set the Logging information'''
    __cwd__ = "/var/logvisualizer/lv_backend/logs"
    __file__ = '{0}.log'.format(time.strftime("%m-%d-%Y_%H"))
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    # logging.basicConfig(filename='{0}/{1}'.format(__cwd__,__file__),
    #                      format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    #                      filemode='w')
    logging.basicConfig(filename='{0}/{1}'.format(__cwd__, __file__), level=logging.DEBUG,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                        datefmt='%d-%b-%y %H:%M:%S',filemode='w')
    tic = time.time()
    cl = fun_vos()
    #__log_server_list__ = [__vvb_info__,__ccm_info__,__fin_info__]
    __log_server_list__ = [__fin_info__]
    with ThreadPoolExecutor(max_workers=100) as executor:
        for __log_servers__ in __log_server_list__:
            # SFTP Log Management
            fun_file_management(__log_servers__)
            # VOS pulls
            executor.submit(cl.__vos_x_min_log_pull__(__log_servers__))
    logger.debug("Total time for functions = {0}".format(time.time() - tic))
except Exception as ex:
    print("Exception: " + str(ex))
