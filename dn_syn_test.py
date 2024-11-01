'''
    This sync job provides consistent updates from ldap server for directory number association.  End Users in a
     OU provide a 1:1 correlation to DN routing



'''
import time,logging
import ldap, ldap.schema
import pymongo

# Testing information
username = 'svc_dn@wx005.webexcce.com'
password = 'Password@123!'
search_directory = 'OU=directoryNumbers,DC=wx005,DC=webexcce,DC=com'
ldap_server = 'den01wx005adc01.wx005.webexcce.com'
pymongo_server = '127.0.0.1'
pymong_server_port = '2727'

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



def login(user_info):
    try:
        #TODO: Pull connectioon (username, PWD from DB)
        #Build a client
        ldap_client = ldap.initialize('ldap://{0}'.format(ldap_server))
        ldap_client.set_option(ldap.OPT_REFERRALS, 0)
        logger.debug("Tring to loging {0}".format(username))
        ldap_client.simple_bind_s(username, password)
        logger.debug("LDAP credentials were good!")
        # Great we are connected, lets pull all CONTACTS
        # get-adobject -filter * -SearchBase 'OU=directoryNumbers,DC=wx005,DC=webexcce,DC=com' -Properties *
        searchattrlist = ['cn','telephoneNumber','mobile','name']
        searchfilter = 'objectClass=contact'
        try:
            # Works for Contact lookup
            # res = ldap_client.search_s(search_directory, ldap.SCOPE_SUBTREE)
            # for dn, entry in res:
            #     logger.debug("Looking at {0}".format(dn))
            # Works - Asyn LDAP call is needed to pull  attributes.
            ldap_result_id  = ldap_client.search(search_directory, ldap.SCOPE_SUBTREE, searchfilter, searchattrlist)
            result_set = []
            while 1:
                result_type, result_data = ldap_client.result(ldap_result_id, 0)
                if (result_data == []):
                    break
                else:
                    if result_type == ldap.RES_SEARCH_ENTRY:
                        result_set.append(result_data)
            logger.debug("{0}".format(result_set))
            #mod_attrs = [( ldap.MOD_REPLACE, "mobile", b"5126636278")]
            #ldap_client.modify_s('CN=2145551212,OU=directoryNumbers,DC=wx005,DC=webexcce,DC=com', mod_attrs)
            #logger.debug("{0}".format('Mobile number added/updated for 2145551212'))
        except Exception as e:
            logger.debug('Error {0}'.format(e))
    except ldap.INVALID_CREDENTIALS:
        #TODO: Check if user has more then >3 fail logins, is so stop login in and throw Syslog Error
        ldap_client.unbind()
        logger.error("LDAP credentials incorrect!")
    except ldap.BUSY:
        ldap_client.unbind()
        logger.error("LDAP is BUSY!")
    except ldap.CONNECT_ERROR:
        ldap_client.unbind()
        logger.error("LDAP Connection Error!")
    except ldap as e:
        logger.error("Error {0}".format(e))
    except:
        logger.error("Total function error")
    return()



# Used for local testing
if __name__ == "__main__":
    login("test")
