''' This file cleans up files and folders older then 1 day from the directory'''
import os, time, sys, logging, shutil, datetime


class fun_file_management():

    def __init__(self, sftp_upload_dir, log_age):
        try:
            # Get current time
            __now__ = time.time()
            # One day (86400)  (3600)
            __age__ = int(log_age)  
            # Get working sftp base directory
            __cwd__ = sftp_upload_dir[:-1]  ## /data/loguser/upload
            for __app_name__ in os.listdir(__cwd__):
                # Build full directory path for each app
                if __app_name__ != 'instant':
                    __app_folder__ = os.path.join(__cwd__, __app_name__)
                    for __device_name__ in os.listdir(__app_folder__):
                        __device_folder__ = os.path.join(__app_folder__, __device_name__)
                        for __log_name__ in os.listdir(__device_folder__):
                            try:
                                # Build full directory path for individual logs
                                __log_folder__ = os.path.join(__device_folder__, __log_name__)
                                logging.debug("__log_folder__ = {0}".format(__log_folder__))
                                ##logging.debug("log age setting: {0}".format(str(__age__)))
                                if os.stat(__log_folder__).st_mtime < __now__ - __age__:
                                    if os.path.isdir(__log_folder__):
                                        shutil.rmtree(__log_folder__)
                                        logging.debug("Deleted folder {0} because it was older then {1} seconds".format(__log_folder__,__age__))
                                    elif os.path.isfile(__log_folder__):
                                        os.remove(__log_folder__)
                                        logging.debug("Deleted file {0} because it was older then {1} seconds".format(__log_folder__,__age__))
                            except:
                                logging.warning("Error working with {0} in {1}".format(__log_name__,__device_folder__))
            return
        except:
            logging.warning('Unable to clean sftp directory for {0}'.format(sftp_upload_dir))
            return


