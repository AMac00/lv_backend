'''
    This sync job provides consistent updates from ldap server for directory number association.  End Users in a
     OU provide a 1:1 correlation to DN routing



'''
import time,logging
import ldap, ldap.schema
import pymongo
#test

# Testing information
username = 'svc_dn@wx005.webexcce.com'
password = 'Password@123!'
search_directory = 'OU=directoryNumbers,DC=wx005,DC=webexcce,DC=com'
ldap_server = 'den01wx005adc01.wx005.webexcce.com'
pymongo_server = '127.0.0.1'
pymong_server_port = '8444'

# Need because the cron job looks for the local user directory
# __cwd__ = "/var/logger/logs"
'''  Set the Logging information'''
__cwd__ = "/var/logvisualizer/lv_backend/logs"
__file__ = '{0}.log'.format(time.strftime("dn_sync_%m-%d-%Y_%H"))
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
logging.basicConfig(filename='{0}/{1}'.format(__cwd__, __file__), level=logging.DEBUG,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    datefmt='%d-%b-%y %H:%M:%S', filemode='w')
#Console loggind for debugging
consoleHandler = logging.StreamHandler()
logger.addHandler(consoleHandler)






# Used for local testing
if __name__ == "__main__":
    login("test")