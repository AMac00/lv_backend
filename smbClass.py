
'''
 Classclasssmb.base.SharedFile(create_time,last_access_time,last_write_time,last_attr_change_time,file_size,alloc_size,file_attributes,short_name,filename,file_id=None)
'''

##import tempfile
from smb.SMBConnection import SMBConnection
from socket import gethostbyname
import socket
import datetime
import os


def getDurationInHours(sec):
    hours = divmod(sec, 3600)[0]
    return int(hours)

def ensure_dir(file_path):
    ##directory = os.path.dirname(file_path)
    print('inside function...')
    try:
        if not os.path.exists(file_path):
            os.makedirs(file_path)
    except Exception as e:
        print('Exception' + str(e))



#######################################################
username = 'jchen'
password = 'Monday#1'
domain = 'lab'
server_ip = '10.1.34.7'
port = 445
share_name = 'VXMLServer'
toplevel = '/applications/'
appArr = []
logTypes = ['ActivityLog', 'ErrorLog']
sftpBasedDir = '/data/loguser/upload/instant/cvpvxml/'
logTimeThresholdInHr = 2900  ## 24 hour in production
######################################################

try:
    conn = SMBConnection(username, password, socket.gethostname(), server_ip, domain, is_direct_tcp=True)
    assert conn.connect(server_ip, port)
 
    shares = conn.listShares()

    for share in shares:
        if not share.isSpecial and share.name not in ['NETLOGON', 'SYSVOL'] and (share.name == share_name):
            sharedfiles = conn.listPath(share.name, toplevel)
            for sharedfile in sharedfiles:
                if (sharedfile.filename != '.' and sharedfile.filename != '..'):
                    #print(sharedfile.filename, sharedfile.create_time, sharedfile.file_attributes, sharedfile.isDirectory )
                    ##print('converted time in utc: ' + sharedfile.filename + ' | '  + datetime.datetime.fromtimestamp(sharedfile.last_write_time).strftime('%Y-%m-%d %H:%M:%S')) ## %c
                    appArr.append(sharedfile.filename)
    
    ### Create directory is not existed ###
    ensure_dir(sftpBasedDir + server_ip)

    now = datetime.datetime.now()
    dt_str = now.strftime('%Y-%m-%d %H:%M:%S')
    print('current utc date and time = ' + dt_str)
    ## Download files from the remote share. ##    
    ##for file in files:
    ##    with open(file, 'wb') as file_obj:
    ##        conn.retrieveFile(share_name,path + file,file_obj)

    for logtype in logTypes:   
        for app in appArr:
            print(sftpBasedDir + server_ip + '/' + app)
            ##ensure_dir(sftpBasedDir + server_ip + '/' + app)
            logDir = '/applications/' + app + '/logs/' + logtype + '/'
            print('logDir => ' + logDir)
            for share in shares:
                if not share.isSpecial and share.name not in ['NETLOGON', 'SYSVOL'] and (share.name == share_name):
                    sharedfiles = conn.listPath(share.name, logDir)
                    for sharedfile in sharedfiles:
                        if (sharedfile.filename != '.' and sharedfile.filename != '..'):
                            ##print('converted time in utc: ' + sharedfile.filename + ' | '  + datetime.datetime.fromtimestamp(sharedfile.last_write_time).strftime('%Y-%m-%d %H:%M:%S'))
                            if  (getDurationInHours((now - datetime.datetime.fromtimestamp(sharedfile.last_write_time)).total_seconds()) < logTimeThresholdInHr):
                                print('converted time in utc: ' + sharedfile.filename + ' | '  + datetime.datetime.fromtimestamp(sharedfile.last_write_time).strftime('%Y-%m-%d %H:%M:%S'))                               
                                dirDownload = sftpBasedDir + server_ip + '/' + app + '/' + logtype
                                ensure_dir(sftpBasedDir + server_ip + '/' + app)
                                ensure_dir(dirDownload) 
                                fileDownload =  dirDownload + '/' + sharedfile.filename
                                with open(fileDownload, 'wb') as file_obj:
                                    conn.retrieveFile(share_name, logDir + sharedfile.filename, file_obj)


    conn.close()
    print('Files retrieved!')
except Exception as ex:
    print('Exception: ' + str(ex))
