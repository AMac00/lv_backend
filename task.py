# Model / Function Imports
from models.fun_applog import fun_applog
## from models.fun_filemanagement import fun_file_management
import logging, time, os
from logging.handlers import RotatingFileHandler
## from env_config import ProductionConfig

######################################################
#  Run by cron job (Schedule job to collect ucce logs)
######################################################

try:
    # Need because the cron job looks for the local user directory
    ##__cwd__ = "/var/logger/logs"
    '''  Set the Logging information'''
    __cwd__ = "/var/logvisualizer/lv_backend/logs"
    __file__ = '{0}.log'.format(time.strftime("%m-%d-%Y_%H"))
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logging.basicConfig(filename='{0}/{1}'.format(__cwd__, __file__), level=logging.DEBUG,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                        datefmt='%d-%b-%y %H:%M:%S',filemode='w')
    currentHr = time.strftime("%H")
    logger.debug('Current hour: {0}'.format(currentHr))
    __fun_applog__ =  fun_applog()
    if currentHr == '06':  ## start log cleanup job in mid-night hour
        __fun_applog__.clean_logs()
    applist = 'cucm,vvb,cvpvxml,cvp,fin,pg,rtr'
    payload = { 'applications': applist, 'instant': 'wxcce' }  
    __fun_applog__.sched_logging_pull(payload)        
except Exception as ex:
    ## print("Exception: " + str(ex))
    logger.debug('Exception [Schedule Task Main Func]: ' + str(ex) )
