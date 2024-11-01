
Log Visualizer Server Configuration


#################################################
## Steps to setup LV Backend and Frontend 
## Date: 1/7/2021
#################################################
Step - 1
### Upload backend and frontend components to LV server ###
1. Download lv_backend from DevOps [https://dev.azure.com/TTECDevOpsTeam/LogVisualizer-Deprecated/_git/lv_backend] 
   unzip and upload lv_backend(folder) to LV server under /var/logvisualizer
2. chmod 777 /var/logvisualizer/lv_backend
3. Download dist from DevOps [https://dev.azure.com/TTECDevOpsTeam/LogVisualizer-Deprecated/_git/lv_frontend_dist] 
   unzip and upload dist(folder) to LV server under /var/logvisualizer
4. chmod 777 /var/logvisualizer/dist


Step - 2
#### Add sftp user and group ####
groupadd sftpusers
useradd -g sftpusers -d /upload -s /sbin/nologin loguser
passwd loguser
mkdir -p /data/loguser/upload
chown -R root:sftpusers /data/loguser
chown -R loguser:sftpusers /data/loguser/upload


Step - 3
######## Update sshd_config:  vi /etc/ssh/sshd_config #########
Match Group sftpusers
ChrootDirectory /data/%u
ForceCommand internal-sftp

==> 
systemctl restart sshd


Step - 4
#### Update lv_backend .sock file  #####
## create service in /etc/systemd/system ##
vi lvapi.service
--
Lvapi.service
[Unit]
Description=Gunicorn service for Log Visualizer
After=network.target

[Service]
User=root
Group=lvgroup
WorkingDirectory=/var/logvisualizer/lv_backend
Environment="PATH=/var/logvisualizer/lv_backend"
ExecStart=/usr/local/bin/gunicorn --workers 3 --bind unix:lvapi.sock -m 007 -t 6
00 wsgi:app

[Install]
WantedBy=multi-user.target
--

[root@gt-logvisualizer lv_backend]# rm -rf lvapi.sock
[root@gt-logvisualizer lv_backend]# systemctl stop lvapi
[root@gt-logvisualizer lv_backend]# systemctl start lvapi
[root@gt-logvisualizer lv_backend]# systemctl status lvapi


Step - 5
#### Create schedule job (hourly log collection and cleanup old logs at mid-night) ####
crontab -e
0 * * * * $(which python3) /var/logvisualizer/lv_backend/task.py > /dev/null 2>&1


Step - 6
#### Update /var/logvisualizer/lv_backend/models/db_helper.py with production config #####
Cleanup system collections in Mongo db
==> Inject seeding prod data to system collection after update instance data into db_helper.py
python3 db_helper.py


Step - 7
####
i.  Create service account for logging into CVP/Vxml Server if not existed
ii. Share CVP folder with that service account (C:\Cisco\CVP), readonly is ok


Step - 8
####
For CCE PGs ..
i.  Make sure portico is installed and running
ii. Make sure service account can be authenticated into portico portal



#################################################
## Steps to setup LV data collection service
## Date: 1/7/2021
#################################################

1. Download lvdc_backend from DevOps [https://dev.azure.com/TTECDevOpsTeam/LogVisualizer-Deprecated/_git/lvdc_backend] 
   unzip and upload lvdc_backend(folder) to LV server under /var/logvisualizer
2. chmod 777 /var/logvisualizer/lvdc_backend
3. pip install pymssql
4. cd /etc/systemd/system
   vi lvdcapi.service (create this file)
   ------------------------------------
   Lvdcapi.service
   [Unit]
   Description=Gunicorn service for Log Visualizer Data Collector
   After=network.target

   [Service]
   User=root
   Group=lvgroup
   WorkingDirectory=/var/logvisualizer/lvdc_backend
   Environment="PATH=/var/logvisualizer/lvdc_backend"
   ExecStart=/usr/local/bin/gunicorn --workers 3 --bind unix:lvdcapi.sock -m 007 -t
   600 wsgi:app

   [Install]
   WantedBy=multi-user.target
   ---------------------------------------------------

5. Login to Mongo DB and create collection for router call logs
   mongo --port 2727 -u lvuser -p password@123
   > use lvdb
   > db.rtrlog.insert()

 
6. systemctl start lvdcapi
7. systemctl status lvdcapi