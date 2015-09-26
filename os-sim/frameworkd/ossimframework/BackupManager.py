# -*- coding: utf-8 -*-
#
# License:
#
#    Copyright (c) 2003-2006 ossim.net
#    Copyright (c) 2007-2014 AlienVault
#    All rights reserved.
#
#    This package is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; version 2 dated June, 1991.
#    You may not use, modify or distribute this program under any other version
#    of the GNU General Public License.
#
#    This package is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this package; if not, write to the Free Software
#    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
#    MA  02110-1301  USA
#
#
# On Debian GNU/Linux systems, the complete text of the GNU General
# Public License can be found in `/usr/share/common-licenses/GPL-2'.
#
# Otherwise you can read it here: http://www.gnu.org/licenses/gpl-2.0.txt
#

"""@package BackupManager
This module designed to run all the mysql backups operations
"""
import socket
import threading
import random
from  time import time, sleep
import os
import sys
import signal
import glob
import re, string, struct
import Queue
import codecs
from base64 import b64encode
import pickle
from threading import Lock
from datetime import datetime, timedelta,date
import commands
import subprocess
import gzip

import MySQLdb
import MySQLdb.cursors

#
#    LOCAL IMPORTS
#
import Util
from DBConstantNames import *
from OssimDB import OssimDB
from OssimConf import OssimConf, OssimMiniConf
from ConfigParser import ConfigParser
from Logger import Logger


logger = Logger.logger
_CONF = OssimConf()



class DoRestore(threading.Thread):
    """This class is designed to do the restore jobs.
    It runs on a separate thread in process the restores jobs without stops the frameworkd work.
    """
    STATUS_ERROR = -1
    STATUS_OK = 0
    STATUS_WORKING = 1
    STATUS_PENDING_JOB = 2
    PURGE_STATUS_OK = 0
    PURGE_STATUS_WORKING = 1
    PURGE_STATUS_PENDING_JOB= 2
    PURGE_STATUS_ERROR = -1
    def __init__(self):
        threading.Thread.__init__(self)
        self.__status = DoRestore.STATUS_OK
        self.__keepWorking = True
        self.__myDB = OssimDB(_CONF[VAR_DB_HOST],
                              _CONF[VAR_DB_SCHEMA],
                              _CONF[VAR_DB_USER],
                              _CONF[VAR_DB_PASSWORD])
        self.__myDB_connected = False
        self.__bkConfig = {}
        self.__loadConfiguration()
        self.__resetJobParams()
        self.__mutex = Lock()
        self.__mutexPurge = Lock()
        self.__tables = ['acid_event',
                        'reputation_data',
                        'idm_data',
                        'otx_data',
                        'extra_data',]
        self.__msgerror = ""
        self.__purgeStatus = DoRestore.PURGE_STATUS_OK
    def purge_status(self):
        """Returns the purge status code
        """
        return self.__purgeStatus

    def string_status(self):
        '''
        This function returns the status of a purge/restore action
        Called by "backup_status" action asked by web UI
        '''
        # Error
        if self.__status == DoRestore.STATUS_ERROR:
            string = 'status="%s" error="%s"' %(self.__status,self.__msgerror)
        elif self.__purgeStatus == DoRestore.PURGE_STATUS_ERROR:
            string = 'status="%s" error="%s"' %(self.__purgeStatus,self.__msgerror)
        # Pending, Running or Stopped
        else:
            # Purge mode first (does not matter if Restore mode were first)
            if self.__purgeStatus > 0:
                string ='status="%s"' % self.__purgeStatus
            elif self.__status > 0:
                string ='status="%s"' % self.__status
            else:
                string ='status="0"'
        
        return string

    def __resetPurgeParams(self):
        """Resets all the purge job parameters.
        """
        self.__setStatusPurgeFlag( DoRestore.PURGE_STATUS_OK)
        self.__datelist_to_purge = []
        self.__bbddhost_to_purge = _CONF[VAR_DB_HOST]
        self.__bbdduser_to_purge = _CONF[VAR_DB_USER]
        self.__bbddpasswd_to_purge = _CONF[VAR_DB_PASSWORD]



    def __resetJobParams(self):
        """Resets all the job parameters.
        """
        self.__beginDate = None
        self.__endDate = None
        self.__entity = ""
        self.__newbbdd = False
        self.__bbddhost = _CONF[VAR_DB_HOST]
        self.__bbdduser =  _CONF[VAR_DB_USER]
        self.__bbddpasswd = _CONF[VAR_DB_PASSWORD]



    def __loadConfiguration(self):
        """Load the backup configuration from the database
        """
        if not self.__myDB_connected:
            if self.__myDB.connect():
                self.__myDB_connected = True
            else:
                logger.error("Can't connect to database")
                return
        query = 'select * from config where conf like "%backup%"'
        data = None
        data = self.__myDB.exec_query(query)
        tmpConfig = {}
        if data is not None:
            for row in data:
                if row['conf'] in ['backup_base', 'backup_day', 'backup_dir', 'backup_events', 'backup_store','frameworkd_backup_storage_days_lifetime']:
                    self.__bkConfig[row['conf']] = row['value']


    def __setStatusPurgeFlag(self,value):
        """Set the purge task status
        """
        self.__mutexPurge.acquire()
        logger.info("purge status :%s" % value)
        self.__purgeStatus = value
        self.__mutexPurge.release()


    def __setStatusFlag(self,value):
        """Sets the status flag
        """
        self.__mutex.acquire()
        self.__status = value
        logger.info("Change status status = %s" %(self.__status))
        self.__mutex.release()

    def status(self):
        """Returns the job status.
        """
        return self.__status


    def setJobParams(self,dtbegin,dtend,entity,newbbdd,bbddhost,bbdduser,bbddpasswd):
        """Set the params for  a restore job.
        @param dtbegin datetime: restore begin date
        @param dtend datetime: restore end date
        @param entity uuid string: entity whose events we want to restore
        @param newbbdd string: Indicates if we want to use a new database to restore the backup
        @param bbddhost string:[used only when newbbdd = 1] Database host
        @param bbdduser string: [used only when newbbdd = 1] Database user
        @param bbddpasswd string: [used only when newbbdd =1] Database password
        """
        self.__msgerror=""
        logger.info("""
        backup restore
        begin %s
        end %s
        entity %s
        newbbdd: %s
        bbddhost:%s
        bbdduser:%s
        
        """ %(dtbegin,dtend,entity,newbbdd,bbddhost,bbdduser))
        self.__beginDate = dtbegin
        self.__endDate = dtend
        self.__newbbdd = newbbdd
        self.__entity = entity
        if bbddhost!= None and bbddhost!= "":
            self.__bbddhost = bbddhost
        if bbdduser != None and bbdduser!="":
            self.__bbdduser =  bbdduser
        if bbddpasswd != None and bbddpasswd!="":
            self.__bbddpasswd = bbddpasswd
        self.__setStatusFlag(DoRestore.STATUS_PENDING_JOB)


    def emptyString(self,value):
        """Check if a string is empty or none.
        """
        if value== None or value == "":
            return True
        else:
            return False

    def setPurgeJobParams(self,datelist,bbddhost,bbdduser,bbddpasswd):
        """Set the data to the job params.
        """
        self.__setStatusPurgeFlag( DoRestore.PURGE_STATUS_PENDING_JOB)
        self.__datelist_to_purge = datelist
        self.__bbddhost_to_purge = bbddhost
        self.__bbdduser_to_purge = bbdduser
        self.__bbddpasswd_to_purge = bbddpasswd


    def __do_purgeEvents(self):
        """Removes the events from the datelist.
        """
        bbddhost = self.__bbddhost_to_purge
        bbdduser =  self.__bbdduser_to_purge
        bbddpasswd = self.__bbddpasswd_to_purge
        datelist = self.__datelist_to_purge

        self.__setStatusPurgeFlag( DoRestore.PURGE_STATUS_WORKING)
        if self.emptyString(bbddhost):
            bbddhost = self.__bbddhost
        if self.emptyString(bbdduser):
            bbdduser = self.__bbdduser
        if self.emptyString(bbddpasswd):
            bbddpasswd = self.__bbddpasswd
        deletes = []
        for date in datelist:
              deletestr = "delete-%s.sql.gz" % date.replace('-','')
              logger.info("Adding delete: %s" % deletestr)
              deletes.append(os.path.join(self.__bkConfig['backup_dir'],deletestr))

        for filename in glob.glob(os.path.join(self.__bkConfig['backup_dir'], 'delete-*.sql.gz')):
            if filename in deletes:
                logger.info("Running delete...%s" % filename)
                fdate = re.sub(r'.*(\d\d\d\d)(\d\d)(\d\d).*', '\\1-\\2-\\3', filename)
                cmd = "mysql --host=%s --user=%s --password=%s  alienvault_siem < $FILE; echo \"CALL alienvault_siem.fill_tables('%s 00:00:00','%s 23:59:59');\" | mysql --host=%s --user=%s --password=%s alienvault_siem" % (bbddhost, bbdduser, bbddpasswd, fdate, fdate, bbddhost, bbdduser, bbddpasswd)
                random_string = ''.join(random.choice(string.ascii_uppercase) for x in range(10))
                ff = gzip.open(filename, 'rb')
                data = ff.read()
                ff.close()
                tmpfile = '/tmp/%s.sql' % random_string
                fd = open(tmpfile,'w')
                fd.write(data)
                fd.close()
                os.chmod(tmpfile, 0644)
                cmd = cmd.replace('$FILE',tmpfile)
                logger.info("Running purge events from %s to %s" % (fdate, fdate))
                status, output = commands.getstatusoutput(cmd)
                if status != 0:
                    logger.error("Error running purge: %s" % output)
                    self.__msgerror = "Error running purge: %s" % output
                    self.__setStatusFlag(DoRestore.STATUS_ERROR)
                    return
                else:
                    logger.info("purge :%s ok" % cmd)
                os.remove(tmpfile)
        #self.__setStatusPurgeFlag(DoRestore.PURGE_STATUS_OK)
        self.__resetPurgeParams()


    def __getCreateTableStatement(self,host,user,password,database,tablename,gettemporal):
        """Returns the create table statement.
        @param host string: Database host
        @param user string: Database user
        @param password string: Database password
        @param database string: Database scheme name
        @param tablename string: Database table name
        @param gettemporal bool: Indicates if we want the real create table statment 
                                 or we want an create temporary table statement.
        """
        #mysqldump -u root -pnMMZ9yFuSu alienvault_siem acid_event --no-data
        create_table_statement = ""
        cmd = "mysqldump -h %s -u %s -p%s %s %s --no-data" % (host,\
                user,password,database,tablename)

        try:
            status,output = commands.getstatusoutput(cmd)
            if status == 0:
                logger.info("create table statement retreived ok")
                create_table_statement = output
            else:
                logger.error("create table statement fail status:%s output:%s" %(status,output))
        except Exception,e:
            logger.error("Create table statment fail: %s" % str(e))

        create_table_statement = create_table_statement.lower()
        lines = []
        if gettemporal:
            lines.append('use alienvault_siem_tmp;')
        for line in create_table_statement.split('\n'):
            if not  line.startswith('/*!') and not line.startswith('--'):
                lines.append(line)
        create_table_statement = '\n'.join(lines)
        return create_table_statement


    def __getIsOldDump(self, backupfile):
        """Checks if a backup file is a backup from 
        the alienvault 4 or older.
        @param backupfile - File to restore
        """
        cmd_check = "zcat %s | grep \"Database: alienvault_siem\"" % backupfile
        status,output = commands.getstatusoutput(cmd_check)
        logger.info("status: %s output: %s" %(status,output))
        if status!=0:
            return True
        return False


    def __setError(self,msg):
        """Sets the error status
        """
        logger.error(msg)
        self.__msgerror = msg
        self.__setStatusFlag(DoRestore.STATUS_ERROR)


    def __unzipBackupToFile(self, backupfile, outputfile):
        """Unzip a backup file to the outputfile
        """
        rt = True
        try:
            cmd = "gunzip -c %s > %s" % (backupfile, outputfile)
            status, output = commands.getstatusoutput(cmd)
            if status != 0:
                self.__setError("Error decompressing the file '%s': %s " % (backupfile, output))
                return False

            os.chmod(outputfile, 0644)
        except Exception,e:
            self.__setError("Error decompressing the file %s " % backupfile)
            rt = False
        return rt


    def __doOldRestore(self,backupfile):
        """Restore an alienvault 3 backup inside the alienvault4 database.
        @param backupfile: File to restore
        """
        logger.info("OLDRESTORE Running restore database from version 3 to version 4")
        # 1 - Create a temporal schemes
        cmd = "mysql -h %s -u %s -p%s -e \"drop database IF EXISTS snort_tmp;create database IF NOT EXISTS snort_tmp;\"" % \
            (self.__bbddhost,self.__bbdduser,self.__bbddpasswd)
        status, output = commands.getstatusoutput(cmd)
        if status != 0:
            self.__setError("OLDRESTORE Error creating the temporal snort database (%s:%s)" %(status,output))
            return False
        
        # 2 - Create the database schema
        cmd = "mysqldump --no-data -h %s -u %s -p%s snort > /tmp/snort_schema.sql" % \
            (self.__bbddhost,self.__bbdduser,self.__bbddpasswd)
        status, output = commands.getstatusoutput(cmd)
        if status != 0:
            self.__setError("OLDRESTORE Can't dump the database schema (%s:%s)" %(status,output))
            return False
        logger.info("OLDRESTORE schema dumped ok..")
        
        cmd = "mysql --host=%s --user=%s --password=%s  snort_tmp < /tmp/snort_schema.sql" \
            % (self.__bbddhost, self.__bbdduser,self.__bbddpasswd)
        
        status, output = commands.getstatusoutput(cmd)
        if status != 0:
            self.__setError("OLDRESTORE Can't dump the database estructure (%s:%s)" %(status,output))
            return False

        
        # 3 - Dump the backup file to the temporal database
        logger.info("OLDRESTORE - Dumping the file to the temporal database...")
        random_string = ''.join(random.choice(string.ascii_uppercase) for x in range(10))
        tmpfile = '/tmp/%s.sql' % random_string
        if not self.__unzipBackupToFile(backupfile,tmpfile):
            self.__setError("Error building the temporal file...")
            return False

        restore_command = "mysql --host=%s --user=%s --password=%s  snort_tmp < $FILE" \
            % (self.__bbddhost, self.__bbdduser,self.__bbddpasswd)
        cmd = restore_command.replace('$FILE',tmpfile)
        status, output = commands.getstatusoutput(cmd)

        if status != 0:
            self.__setError("OLDRESTORE Can't dump the database data (%s:%s)" %(status,output))
            return False
        
        
        # 4 - Running migrate script
        
        cmd = "/usr/share/ossim/scripts/migrate_snort.pl snort_tmp"
        if not self.emptyString(self.__entity):
            cmd = "/usr/share/ossim/scripts/migrate_snort.pl snort_tmp %s" % self.__entity
        status, output = commands.getstatusoutput(cmd)
        if status != 0:
            self.__setError("OLDRESTORE Migrate script fails: %s-%s" %(status,output))
            return False
        logger.info("OLDRESTORE Restore has been successfully executed")
        try:
            os.remove(tmpfile)
            os.remove('/tmp/snort_schema.sql')
        except:
            pass
        return True


    def __doRestoreWithoutEntity(self, backupfile):
        """Restores the backup file regardless of the entity
        @param bakcupfile file to restore
        """
        tmpfile = "/tmp/set.sql"
        createtmpdatabase = open(tmpfile,'w')
        createtmpdatabase.write("SET UNIQUE_CHECKS=0;SET @disable_count=1;\n")
        createtmpdatabase.close()
        try:
            status, output = commands.getstatusoutput("pigz %s" % tmpfile)
            if status != 0:
                self.__setError("Error gzipping %s" % tmpfile)
                return False
        except Exception, e:
            self.__setError("Error gzipping %s" % tmpfile)
            return False
        
        fdate = re.sub(r'.*(\d\d\d\d)(\d\d)(\d\d).*', '\\1-\\2-\\3', backupfile)
        restore_command = "zcat %s.gz %s | grep -i ^insert | mysql --host=%s --user=%s --password=%s alienvault_siem; echo \"CALL alienvault_siem.fill_tables('%s 00:00:00','%s 23:59:59');\" | mysql --host=%s --user=%s --password=%s alienvault_siem; rm -f %s.gz" % \
                          (tmpfile, backupfile, self.__bbddhost, self.__bbdduser, self.__bbddpasswd, fdate, fdate, self.__bbddhost, self.__bbdduser, self.__bbddpasswd, tmpfile)
        logger.info("Running restore ")
        try:
            status, output = commands.getstatusoutput(restore_command)
            if status != 0:
                self.__setError("Error running restore: %s" % output)
                return False
            else:
                logger.info("Restore OK")
        except Exception, e:
            self.__setError("Error restoring backup '%s': %s" % (backupfile, str(e)))
            return False

        return True


    def __createTmpAlienvaultSiemDB(self):
        """Creates the alienvault_siem_tmp database
        """
        tmpfile = "/tmp/createdb.sql"
        createtmpdatabase = open(tmpfile,'w')
        createtmpdatabase.write("DROP DATABASE IF EXISTS alienvault_siem_tmp;\n")
        createtmpdatabase.write("CREATE DATABASE alienvault_siem_tmp;\n")
        # Create the temporary tables.
        for table in self.__tables:
            createtmpdatabase.write(self.__getCreateTableStatement(self.__bbddhost,self.__bbdduser,self.__bbddpasswd,'alienvault_siem',table,True))
        createtmpdatabase.close()
        createdb_command = "mysql --host=%s --user=%s --password=%s < %s" % (self.__bbddhost, self.__bbdduser,self.__bbddpasswd,tmpfile)
        status, output = commands.getstatusoutput(createdb_command)
        if status!=0:
            self.__setError("Can't create temporal db %s" % output)
            return False
        return True


    def __doRestore(self,filename):
        """Restores the backup file taiking into account the entity
        @param bakcupfile file to restore
        """
        try:
            restore_command = "mysql --host=%s --user=%s --password=%s alienvault_siem_tmp < $FILE" % \
                        (self.__bbddhost, self.__bbdduser,self.__bbddpasswd)
            # 1 - Create a temporal database
            if not self.__createTmpAlienvaultSiemDB():
                return False
            db = MySQLdb.connect(host=self.__bbddhost, user=self.__bbdduser,\
                                                   passwd=self.__bbddpasswd)
            db.autocommit(True)
            cursor  = db.cursor()

            # 2 - Unzip the backup file
            random_string = ''.join(random.choice(string.ascii_uppercase) for x in range(10))
            tmpfile = '/tmp/%s.sql' % random_string
            if not self.__unzipBackupToFile(filename,tmpfile):
                self.__setError("Unable to decompress the backup file")
                return False
            # 3 - Dumps the backup over the tmp database
            try:
                cmd = restore_command.replace('$FILE',tmpfile)
                status, output = commands.getstatusoutput(cmd)
                os.remove(tmpfile)
            except Exception,e:
                self.__setError(str(e))
                return False
            # 4 - Now remove all the data that do not belongs to the entity.A
            logger.info("Removing data from other entities")
            query_remove_acid_event = "delete from alienvault_siem_tmp.acid_event where ctx!=unhex('%s')"% self.__entity.replace('-','')
            logger.info("Removing data from acid event: %s" % query_remove_acid_event)
            cursor.execute(query_remove_acid_event)
            cursor.fetchall()

            query_remove_reptutation= "delete from alienvault_siem_tmp.reputation_data where event_id not in (select event_id from alienvault_siem_tmp.acid_event)"
            logger.info(query_remove_reptutation)
            cursor.execute(query_remove_reptutation)
            cursor.fetchall()

            query_remove_idm_data = "delete from alienvault_siem_tmp.idm_data where event_id not in (select event_id from alienvault_siem_tmp.acid_event)"
            logger.info(query_remove_idm_data)
            cursor.execute(query_remove_idm_data)
            cursor.fetchall()

            query_remove_otx_data = "delete from alienvault_siem_tmp.otx_data where event_id not in (select event_id from alienvault_siem_tmp.acid_event)"
            logger.info(query_remove_otx_data)
            cursor.execute(query_remove_otx_data)
            cursor.fetchall()

            query_remove_extra_data = "delete from alienvault_siem_tmp.extra_data where event_id not in (select event_id from alienvault_siem_tmp.acid_event)"
            logger.info(query_remove_extra_data)
            cursor.execute(query_remove_extra_data)
            cursor.fetchall()
            # 5 - finally record all the data and insert it on alienvault_siem
            #table: acid_event
            querytmp = "select * into outfile '/tmp/acid_event.sql' from alienvault_siem_tmp.acid_event"
            cursor.execute(querytmp)
            cursor.fetchall()

            querytmp =" load data infile '/tmp/acid_event.sql' into table alienvault_siem.acid_event"
            self.__myDB.exec_query(querytmp)

            logger.info("Restored data to acid_event")

            #table: reputation_data:
            querytmp = "select * into outfile '/tmp/reputation_data.sql' from alienvault_siem_tmp.reputation_data"
            cursor.execute(querytmp)
            cursor.fetchall()
            
            querytmp =" load data infile '/tmp/reputation_data.sql' into table alienvault_siem.reputation_data"
            self.__myDB.exec_query(querytmp)
            logger.info("Restored data to reputation_data")

            #table: otx_data:
            querytmp = "select * into outfile '/tmp/otx_data.sql' from alienvault_siem_tmp.otx_data"
            cursor.execute(querytmp)
            cursor.fetchall()
            
            querytmp =" load data infile '/tmp/otx_data.sql' into table alienvault_siem.otx_data"
            self.__myDB.exec_query(querytmp)
            logger.info("Restored data to otx_data")

            #table: idm_data:
            querytmp = "select * into outfile '/tmp/idm_data.sql' from alienvault_siem_tmp.idm_data"
            cursor.execute(querytmp)
            cursor.fetchall()
            querytmp =" load data infile '/tmp/idm_data.sql' into table alienvault_siem.idm_data"
            self.__myDB.exec_query(querytmp)
            logger.info("Restored data to idm_data")

            # 6 - Remove the temporary database and the temporal files
            try:
                query ="DROP DATABASE IF EXISTS alienvault_siem_tmp"
                cursor.execute(query)
                cursor.fetchall()
                os.remove('/tmp/acid_event.sql')
                os.remove('/tmp/reputation_data.sql')
                os.remove('/tmp/otx_data.sql')
                os.remove('/tmp/idm_data.sql')
                cursor.close()
                db.close()
            except Exception,e:
                self.__setError("Error cleaning the data used to restore")
                return False
        except Exception,e:
            self.__setError("Can't do the restore :%s" % str(e))
            return False

        return True


    def __dojob(self):
        """Runs the restore job.
        """
        self.__setStatusFlag(DoRestore.STATUS_WORKING)
        logger.info("Running restore job ....")
        filestorestore = []
        insertfile = "insert-%s.sql.gz" % str(self.__beginDate.date()).replace('-','')
        insertfile = os.path.join(self.__bkConfig['backup_dir'],insertfile)
        filestorestore.append(insertfile)
        total_files = []

        while  self.__endDate>self.__beginDate:
            self.__beginDate = self.__beginDate + timedelta(days=1)
            insertfile = "insert-%s.sql.gz" % str(self.__beginDate.date()).replace('-','')
            insertfile = os.path.join(self.__bkConfig['backup_dir'],insertfile)
            filestorestore.append(insertfile)

        for filename in glob.glob(os.path.join(self.__bkConfig['backup_dir'], 'insert-*.sql.gz')):
            if filename in filestorestore:
                logger.info("Appending file to restore job: %s" % filename)
                total_files.append(filename)

        for filename in total_files:
            rt = True
            if self.__getIsOldDump(filename):
                rt = self.__doOldRestore(filename)
            elif self.emptyString(self.__entity):
                rt = self.__doRestoreWithoutEntity(filename)
            else:
                rt = self.__doRestore(filename)
            if not rt:
                return
        self.__setStatusFlag(DoRestore.STATUS_OK)

    def run(self):
        """Thread entry point.
        Waits until new jobs arrives
        """

        while self.__keepWorking:
            if self.__status == DoRestore.STATUS_PENDING_JOB:
                self.__dojob()
            if self.__purgeStatus == DoRestore.PURGE_STATUS_PENDING_JOB:
                self.__do_purgeEvents()

            sleep(1)


class BackupRestoreManager():
    """Class to manage all the restore request from the web.
    """
    
    def __init__(self,conf):
        """ Default Constructor.
        @param conf OssimConf: Configuration object.
        """
        logger.info("Initializing  BackupRestoreManager")
        self.__conf = conf
        self.__worker = DoRestore()
        self.__worker.start()


    def process(self,message):
        """ Process the requests:
        @param message string: Request to process. 
            Examples:
            backup action="backup_restore"  begin="YYYY-MM-DD" end="YYYY-MM-DD" entity="ab352ced-c83d-4c9b-bc55-aae6c3e0069d" newbbdd="1" bbddhost="192.168.2.1" bbdduser="pepe" bbddpasswd="kktua" \n
            backup action="purge_events" dates="2012-05-12,2012-05-14,2012-05-15" bbddhost="host" bbdduser="kkka2" bbddpasswd="agaag"
            backup action="backup_status"

        """
        response =""
        action = Util.get_var("action=\"([a-z\_]+)\"", message)

        if action=="backup_restore":
            logger.info("Restoring")
            begindate = Util.get_var("begin=\"(\d{4}\-\d{2}\-\d{2})\"",message)
            enddate = Util.get_var("end=\"(\d{4}\-\d{2}\-\d{2})\"",message)
            entity = Util.get_var("entity=\"([a-f0-9]{8}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{12})\"",message.lower())
            newbbdd = Util.get_var("newbbdd=\"(0|1|yes|true|no|false)\"",message.lower())
            bbddhost = Util.sanitize(Util.get_var("bbddhost=\"(\S+)\"",message))
            bbdduser = Util.sanitize(Util.get_var("bbdduser=\"(\S+)\"",message))
            bbddpasswd = Util.sanitize(Util.get_var("bbddpasswd=\"(\S+)\"",message))
            dtbegin=None
            dtend = None
            isnewbbdd = False
            if newbbdd in ["yes","1","True"]:
                isnewbbdd = True
            try:
                dtbegin =  datetime.strptime(begindate,'%Y-%m-%d')
            except Exception,e:
                response = message + ' errno="-1" error="Invalid begin date. Format YYYY-MM-DD"  ackend\n'
                return response
            try:
                dtend= datetime.strptime(enddate,'%Y-%m-%d')
            except Exception,e:
                response = message +  ' errno="-2" error="Invalid end date. Format YYYY-MM-DD" ackend\n'
                return response
            if dtend < dtbegin:
                response = message +  ' errno="-3" error="End date < Begin Date" ackend\n'
                return response

            self.__worker.setJobParams(dtbegin,dtend,entity,newbbdd,bbddhost,bbdduser,bbddpasswd)
            response = message + ' status="%s" ackend\n' % self.__worker.status()
        elif action=="purge_events":
            logger.info("Restoring")
            dates = Util.get_var("dates=\"(\S+)\"",message)
            bbddhost = Util.sanitize(Util.get_var("bbddhost=\"(\S+)\"",message))
            bbdduser = Util.sanitize(Util.get_var("bbdduser=\"(\S+)\"",message))
            bbddpasswd = Util.sanitize(Util.get_var("bbddpasswd=\"(\S+)\"",message))
            datelist = dates.split(',')
            self.__worker.setPurgeJobParams(datelist,bbddhost,bbdduser,bbddpasswd)
            response = message + ' status="%s" ackend\n' % self.__worker.purge_status()

        elif action == "backup_status":
            logger.info("status")
            response = message + ' %s ackend\n' % self.__worker.string_status()
        else:
            response = message + ' errno="-4" error="Unknown command" ackend\n' 

        return response


class BackupManager(threading.Thread):
    """Manage the periodic backups.
    """
    UPDATE_BACKUP_FILE = '/etc/ossim/framework/lastbkday.fkm'
    LISTEN_SOCK = '/etc/ossim/framework/bksock.sock'


    def __init__(self):
        """Default constructor.
        """
        threading.Thread.__init__(self)
        self.__myDB = OssimDB(_CONF[VAR_DB_HOST],
                              _CONF[VAR_DB_SCHEMA],
                              _CONF[VAR_DB_USER],
                              _CONF[VAR_DB_PASSWORD])
        self.__myDB_connected = False
        self.__keepWorking = True
        #self.__mutex = Lock()
        self.__bkConfig = {}
        self.__loadConfiguration()
        self.__stopE = threading.Event()
        self.__stopE.clear()


    def __loadConfiguration(self):
        """Loads the backup manager configuration and updates it with the database values.
        """
        self.__loadBackupConfig()
        if not self.__myDB_connected:
            if self.__myDB.connect():
                self.__myDB_connected = True
            else:
                logger.error("Can't connect to database")
                return
        query = 'select * from config where conf like "%backup%"'
        data = None
        data = self.__myDB.exec_query(query)
        tmpConfig = {}
        if data is not None:
            for row in data:
                if row['conf'] in ['backup_base', 'backup_day', 'backup_dir', 'backup_events', 'backup_store','frameworkd_backup_storage_days_lifetime', 'backup_hour']:
                    tmpConfig [row['conf']] = row['value']

        for key, value in tmpConfig.iteritems():
            if key == 'last_run':
                continue
            if key not in self.__bkConfig:
                logger.info("Backup new config key: '%s' '%s'" % (key, value))
                self.__bkConfig[key] = tmpConfig[key]
            elif value != self.__bkConfig[key]:
                logger.info('Backup Config value has changed %s=%s and old value %s=%s' % (key, value, key, self.__bkConfig[key]))
                self.__bkConfig[key] = tmpConfig[key]

        if not self.__bkConfig.has_key('last_run'):
            self.__bkConfig['last_run'] = date(year=1,month=1,day=1)
        if not self.__bkConfig.has_key('backup_day'):
            self.__bkConfig['backup_day'] = 30
        if not self.__bkConfig.has_key('frameworkd_backup_storage_days_lifetime'):
            self.__bkConfig['frameworkd_backup_storage_days_lifetime'] = 5

        self.__updateBackupConfigFile()


    def __updateBackupConfigFile(self):
        """Update the backup configuration file
        """
        try:
            bk_configfile = open(BackupManager.UPDATE_BACKUP_FILE, "wb")
            pickle.dump(self.__bkConfig, bk_configfile)
            bk_configfile.close()
            os.chmod(BackupManager.UPDATE_BACKUP_FILE,0644)
        except Exception, e:
            logger.error("Error dumping backup config update_file...:%s" % str(e))


    def __loadBackupConfig(self):
        """Load the backup configuration from the backup file
        """
        self.__bkConfig = {}

        if os.path.isfile(BackupManager.UPDATE_BACKUP_FILE):
            try:
                bk_configfile = open(BackupManager.UPDATE_BACKUP_FILE)
                self.__bkConfig = pickle.load(bk_configfile)
                bk_configfile.close()
                if not isinstance(self.__bkConfig, dict):
                    logger.warning("Error loading backup configuration file.")
                    logger.info("New configuration will be loaded from database")
                    self.__bkConfig = {}
            except Exception, e:
                logger.warning("Error loading backup configuration file...:%s" % str(e))
                logger.info("New configuration will be loaded from database")
                self.__bkConfig = {}



    def purgeOldBackupfiles(self):
        """Purge old backup files.
        """
        #logger.info("Purge old bakcups")
        backup_files = []
        bkdays = 5
        try:
            bkdays = int(_CONF[VAR_BACKUP_DAYS_LIFETIME])
        except ValueError,e:
            logger.warning("Invalid value for backup_day in config table")
        today = datetime.now() - timedelta(days=1)
        while bkdays>0:
            dt = today.date().isoformat()
            dtstr = "%s" % dt
            dtstr = dtstr.replace('-','')
            str_insert = '%s/insert-%s.sql.gz' % (self.__bkConfig['backup_dir'], dtstr)
            str_delete = '%s/delete-%s.sql.gz' % (self.__bkConfig['backup_dir'], dtstr)
            backup_files.append(str_insert)
            backup_files.append(str_delete)
            bkdays = bkdays - 1
            today = today -timedelta(days=1)

        for bkfile in glob.glob(os.path.join(self.__bkConfig['backup_dir'], '[insert|delete]*.sql.gz')):
            bkfilep=os.path.join(self.__bkConfig['backup_dir'], bkfile)
            if bkfilep not in backup_files:
                logger.info("Removing outdated backfile :%s" % bkfilep)
                try:
                    os.unlink(bkfilep)
                except Exception,e:
                    logger.error("Error removing outdated files: %s" % bkfilep)


    def get_current_backup_files(self):
        backup_files = []
        try:
            #for bkfile in glob.glob(os.path.join(self.__bkConfig['backup_dir'], 'insert*.sql.gz')):
            backup_files = glob.glob(os.path.join(self.__bkConfig['backup_dir'], 'insert*.sql.gz'))
        except Exception as err:
            logger.error("An error occurred while reading the current database backups %s" % str(err))
        return backup_files

    def checkDiskUsage(self):
        """Check max disk usage.
        """
        mega = 1024 * 1024
        disk_state = os.statvfs('/var/ossim/')
        #free space in megabytes.
        capacity = float((disk_state.f_bsize * disk_state.f_blocks)/mega)
        free_space = float( (disk_state.f_bsize * disk_state.f_bavail) / mega)
        percentage_free_space = (free_space * 100)/capacity
        min_free_space_allowed  = 10
        try:
            min_free_space_allowed = 100 - int(_CONF[VAR_BACKUP_MAX_DISKUSAGE])
        except Exception,e:
            logger.error("Error when calculating free disk space: %s" % str(e))

        logger.debug("Min free space allowed: %s - current free space: %s" %(min_free_space_allowed,percentage_free_space))
        if percentage_free_space < min_free_space_allowed:
            return False
        return True


    def __createDeleteBkFile(self):
        """Creates the delete file for today
        """
        
        last_day = datetime.now() - timedelta(days=int(self.__bkConfig[VAR_BACKUP_DAYS_LIFETIME]))
        today_date = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        while last_day < today_date:
            date = last_day.date()
            daystr = '%s' % date
            daystr = daystr.replace('-', '')
            deletefilename = '%s/delete-%s.sql.gz' % (self.__bkConfig['backup_dir'], daystr)
            if not os.path.exists(deletefilename):
                delete_file = gzip.open(deletefilename,'w')
                initd = last_day.replace(hour=0, minute=0, second=0, microsecond=0)
                endd = last_day.replace(hour=23, minute=59, second=59, microsecond=0)
                try:
                    
                    delete_file.write("DELETE aux FROM alienvault_siem.idm_data aux INNER JOIN alienvault_siem.acid_event aa ON aux.event_id=aa.id WHERE aa.timestamp between '%s' and '%s';\n" % (initd, endd))
                    delete_file.write("DELETE aux FROM alienvault_siem.reputation_data aux INNER JOIN alienvault_siem.acid_event aa ON aux.event_id=aa.id WHERE aa.timestamp between '%s' and '%s';\n" % (initd, endd))
                    delete_file.write("DELETE aux FROM alienvault_siem.otx_data aux INNER JOIN alienvault_siem.acid_event aa ON aux.event_id=aa.id WHERE aa.timestamp between '%s' and '%s';\n" % (initd, endd))
                    delete_file.write("DELETE aux FROM alienvault_siem.extra_data aux INNER JOIN alienvault_siem.acid_event aa ON aux.event_id=aa.id WHERE aa.timestamp between '%s' and '%s';\n" % (initd, endd))
                    delete_file.write("DELETE FROM alienvault_siem.ac_acid_event WHERE timestamp BETWEEN '%s' AND '%s';\n" % (initd, endd))
                    delete_file.write("DELETE FROM alienvault_siem.po_acid_event WHERE timestamp BETWEEN '%s' AND '%s';\n" % (initd, endd))
                    delete_file.write("SET @disable_del_count = 1;\nDELETE FROM alienvault_siem.acid_event WHERE timestamp between '%s' and '%s';\nSET @disable_del_count = null;\n" % (initd, endd))
                    delete_file.close()
                    os.chmod(deletefilename, 0644)
                except Exception,e:
                    logger.info("Error creating delete backup file")
            last_day = last_day + timedelta(days=1)

        return True

    def __is_process_running(self, process_name=""):
        """
        Check if there is a process running in the system
        """
        try:
            num_process = int(commands.getoutput("ps auxwww | grep %s | grep -v grep | grep -v tail | wc -l" % process_name))
            if num_process > 0:
                return True
        except Exception, e:
            logger.warning("Error checking process status '%s': %s" % process_name, str(e))

        return False

    def __shouldRunBackup(self):
        """Checks if it should runs a new backup.
        Backup Hour: By default every day at 01:00:00
        """
        now = datetime.now()
        backup_hour = now.replace(year=self.__bkConfig['last_run'].year,
                                  month=self.__bkConfig['last_run'].month,
                                  day=self.__bkConfig['last_run'].day,
                                  hour=1,
                                  minute=0,
                                  second=0) + timedelta(days=1)

        if 'backup_hour' in self.__bkConfig:
            try:
                (config_backup_hour, config_backup_minute) = self.__bkConfig['backup_hour'].split(':')
                backup_hour = backup_hour.replace(hour=int(config_backup_hour),
                                                  minute=int(config_backup_minute))

            except Exception, e:
                print str(e)
                logger.warning("Bad parameter in backup_hour config table, using default time (01:00:00 Local time)")

        # Run backups when:
        # - It has reached the backup hour
        # - alienvault-reconfig is not running
        # - alienvault-update is not running
        if backup_hour > now:
            return False
        if self.__is_process_running('alienvault-reconfig'):
            logger.info("There is a alienvault-reconfig proccess running. Cannot run a Backup at this time")
            return False
        if self.__is_process_running('alienvault-update'):
            logger.info("There is a alienvault-update proccess running. Cannot run a Backup at this time")
            return False

        return True

    def __delete_events_older_than_timestamp(self, limit_date):
        """
        Delete all the events older than %limit_date
        """
        deletes = []
        total_events = 0

        # Get the date of the oldest event in database
        begin_date = self.__getOldestEventInDatabaseDateTime()

        # Runs the deletes...
        while begin_date < limit_date:
            end_date = begin_date.replace(hour=23, minute=59, second=59, microsecond=0)
            query = ""
            if end_date > limit_date:
                end_date = limit_date
                query = "SELECT COUNT(id) AS total FROM alienvault_siem.acid_event WHERE timestamp BETWEEN '%s' AND '%s';" % (begin_date, end_date)
            else:
                query = "SELECT ifnull(SUM(cnt),0) AS total FROM alienvault_siem.ac_acid_event WHERE timestamp BETWEEN '%s' AND '%s';" % (begin_date, end_date)
            query_result = self.__myDB.exec_query(query)
            if len(query_result) == 1:
                events_to_delete = query_result[0]['total']
                total_events += events_to_delete
                if events_to_delete != 0:
                    logger.info("Events to delete: '%s' events from %s to %s" % (events_to_delete, begin_date, end_date ))

                    # Delete acumulate tables entries
                    deletes.append("DELETE FROM alienvault_siem.ac_acid_event WHERE timestamp <= '%s';" % end_date)
                    deletes.append("DELETE FROM alienvault_siem.po_acid_event WHERE timestamp <= '%s';" % end_date)
 
                    block = 100000

                    delete_tmp_table = "alienvault_siem.backup_delete_temporal"
                    delete_mem_table = "alienvault_siem.backup_delete_memory"

                    # Get the event ids from begin_date to end_date to delete
                    deletes.append("CREATE TABLE IF NOT EXISTS %s (id binary(16) NOT NULL, PRIMARY KEY (id));" % delete_tmp_table)
                    deletes.append("TRUNCATE TABLE %s;" % delete_tmp_table)
                    deletes.append("INSERT IGNORE INTO %s SELECT id FROM alienvault_siem.acid_event WHERE timestamp BETWEEN '%s' and '%s';" % (delete_tmp_table, begin_date, end_date))
                    deletes.append("CREATE TEMPORARY TABLE %s (id binary(16) NOT NULL, PRIMARY KEY (`id`)) ENGINE=MEMORY;" % (delete_mem_table))

                    # Delete by blocks
                    for limit in range(0, events_to_delete + 1, block):
                        deletes.append("INSERT INTO %s SELECT id FROM %s LIMIT %d;" % (delete_mem_table, delete_tmp_table, block))
                        deletes.append("CALL alienvault_siem.delete_events('%s');" % (delete_mem_table))
                        deletes.append("DELETE t FROM %s t, %s m WHERE t.id=m.id;" % (delete_tmp_table, delete_mem_table))
                        deletes.append("TRUNCATE TABLE %s;" % (delete_mem_table))

                    deletes.append("DROP TABLE %s;" % (delete_mem_table))
                    deletes.append("DROP TABLE %s;" % (delete_tmp_table))

                # Go to the next date
                next_date = self.__getOldestEventInDatabaseDateTime(begin_date.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1))

                # Check last day of events
                if begin_date.day == next_date.day:
                    break;

                begin_date = next_date

        logger.info("-- Total events to delete: %s" % total_events)

        for delete in deletes:
            logger.info("Running delete: %s" % delete)
            try:
                self.__myDB.exec_query(delete)
            except Exception, e:
                logger.error("Error running delete: %s" )

    def __deleteByBackupDays(self):
        """Runs the delete command using the backup_day threshold
        """
        #
        # Check by backup days.
        #
        backupdays = 0
        try:
            backupdays = int(self.__bkConfig['backup_day'])
        except Exception, e:
            logger.warning("Invalid value for: Events to keep in the Database (Number of days) -> %s" % self.__bkConfig['backup_day'])
            backupdays = 0

        if backupdays > 0:  # backupdays = 0 unlimited.
            limit_day = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=int(backupdays))
            self.__delete_events_older_than_timestamp(limit_day)
        else:
            logger.info("Unlimited number of events.  Events to keep in the Database (Number of days) = %s" % backupdays)


    def __deleteByNumberOfEvents(self):
        """Runs the delete using the maximum number of events in the database
        as threshold.
        """
        limit_date = None
        #
        # Check by max number of events in the Database.
        #
        max_events = 0
        try:
            max_events = int(self.__bkConfig['backup_events'])
        except Exception,e:
            logger.info("Invalid value for: Events to keep in the Database (Number of events) -> %s" % self.__bkConfig['backup_events'])
            max_events = 0

        if max_events > 0: # backup_events = 0 -> unlimited
            query = "select timestamp from (select timestamp,@total := @total - cnt as total from (alienvault_siem.ac_acid_event, (select @total := (select ifnull(sum(cnt),0) from alienvault_siem.ac_acid_event)) t) order by timestamp asc) as ac where total>%s order by timestamp desc limit 1;" % self.__bkConfig['backup_events']
            data = self.__myDB.exec_query(query)

            if len(data) == 1:
                limit_date = data[0]['timestamp']
                self.__delete_events_older_than_timestamp(limit_date)
        else:
            logger.info("Unlimited number of events.  Events to keep in the Database (Number of events) = %s" % max_events)



    def __getOldestEventInDatabaseDateTime(self, min_timestamp='1900-01-01 00:00:00'):
        """Returns the datetime of the oldest event in the database
        """
        oldestEvent = datetime.now()

        query = 'SELECT min(timestamp) as lastEvent FROM alienvault_siem.acid_event WHERE timestamp > \'%s\';' % (min_timestamp)
        # Get the oldest event from the database and do the backup from that day
        # until yesterday (do if not exists yet).
        data = self.__myDB.exec_query(query)
        if len(data) == 1:
            oldestEvent = data[0]['lastEvent']
            if oldestEvent is None:
                oldestEvent = datetime.now()
            oldestEvent = oldestEvent.replace(hour=0, minute=0, second=0, microsecond=0)
        return oldestEvent


    def __storeBackups(self):
        """Returns if we have to store the backups.
        """
        rt = False
        if self.__bkConfig['backup_store'].lower() in ['1', 'yes', 'true']:
            rt= True
        return rt


    def __isBackupsEnabled(self):
        """Returns if the backups are enabled...
        """
        max_events=0
        try:
            max_events = int(self.__bkConfig['backup_events'])
        except Exception,e:
            logger.info("Invalid value for: Events to keep in the Database (Number of events) -> %s" % self.__bkConfig['backup_events'])
            max_events = 0
        backupdays=0
        try:
            backupdays = int(self.__bkConfig['backup_day'])
        except Exception,e:
            logger.warning("Invalid value for: Events to keep in the Database (Number of days) -> %s" % self.__bkConfig['backup_day'])
            backupdays = 0
        backup_enabled = True
        if max_events  ==0 and backupdays == 0:
            logger.info("Backups are disabled  MaxEvents = 0, BackupDays =0")
            backup_enabled = False
        return backup_enabled


    def __run_backup(self):
        """Run the backup job.
        """
        # Check the disk space
        if not self.checkDiskUsage():
            logger.warning("[ALERT DISK USAGE] Can not run backups due to low free disk space")
            return
        # Purge old backup files
        self.purgeOldBackupfiles()
        backupCMD = "ionice -c2 -n7 mysqldump alienvault_siem $TABLE -h %s -u %s -p%s -c -n -t -f --skip-add-locks --skip-disable-keys --skip-triggers --single-transaction --hex-blob --quick --insert-ignore -w $CONDITION" % (_CONF[VAR_DB_HOST], _CONF[VAR_DB_USER], _CONF[VAR_DB_PASSWORD])

        # Should I  store the backups? -> only if store is true.
        if self.__shouldRunBackup():  # Time to do the backup?
            logger.info("Running backups system...")
            # do backup
            if not self.__myDB_connected:
                if self.__myDB.connect():
                    self.__myDB_connected = True
                else:
                    logger.info("Can't connect to database..")
                    return

            self.__bkConfig['last_run'] = datetime.now().date()
            firstEventDateTime = '1900-01-01 00:00:00'
            firstEventDateTime = self.__getOldestEventInDatabaseDateTime(firstEventDateTime)
            try:
                bkdays = int(_CONF[VAR_BACKUP_DAYS_LIFETIME])
            except ValueError:
                bkdays = 5
            threshold_day = datetime.today()-timedelta(days=bkdays+1)

            if self.__storeBackups() and self.__isBackupsEnabled():
                try:
                    today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
                    current_backups = self.get_current_backup_files()
                    while firstEventDateTime < today:
                        # Changes: #8312
                        # We should create a dump file only for the last bkdays
                        if firstEventDateTime < threshold_day:
                            logger.info("Do not make backup because threshold day: first event datetime: %s, thresholday:%s" % (firstEventDateTime,threshold_day))
                            firstEventDateTime = firstEventDateTime + timedelta(days=1)
                            continue
                        logger.info("="*50+"BACKUP: %s" % firstEventDateTime)
                        backupCmds = {}
                        dateBackup = '%s' % firstEventDateTime.date().isoformat()
                        insert_backupFile = '%s/insert-%s.sql' % (self.__bkConfig['backup_dir'], dateBackup.replace('-', ''))
                        if insert_backupFile+".gz" in current_backups:
                            firstEventDateTime = firstEventDateTime + timedelta(days=1)
                            logger.info("BACKUP %s Ignoring.... backup has already been done" % insert_backupFile)
                            continue
                        #if file is already created, continue
                        if os.path.exists(dateBackup):
                            continue
                        logger.info("New backup file: %s" % insert_backupFile)
                        #######################
                        # ACID EVENT
                        #######################
                        backupACIDEVENT_cmd = backupCMD.replace('$TABLE', 'acid_event')
                        condition = '"timestamp BETWEEN \'%s 00:00:00\' AND \'%s 23:59:59\'"' % (dateBackup, dateBackup)
                        backupACIDEVENT_cmd = backupACIDEVENT_cmd.replace('$CONDITION', condition)
                        backupCmds["%s_%s" % ('acid_event',dateBackup)] = backupACIDEVENT_cmd
                        condition = '"event_id in (SELECT id FROM alienvault_siem.acid_event WHERE timestamp BETWEEN \'%s 00:00:00\' AND \'%s 23:59:59\')"' % (dateBackup, dateBackup)
                        for table in ['reputation_data', 'idm_data', 'otx_data', 'extra_data']:
                            cmd = backupCMD.replace('$TABLE', table)
                            cmd = cmd.replace('$CONDITION', condition)
                            backupCmds['%s_%s' %(table,dateBackup)] = cmd

                        condition = '"day=\'%s\'"' % (dateBackup)

                        backup_data = ""
                        for table_day, cmd in backupCmds.iteritems():
                            cmd = cmd + ">> %s" % insert_backupFile
                            status, output = commands.getstatusoutput(cmd)
                            if status == 0:
                                logger.info("Running Backup for day %s  OK" % table_day)
                            else:
                                logger.error("Error (%s) running: %s" % (status, table_day))
                                return
                        try:
                            status, output = commands.getstatusoutput("pigz -f %s" % insert_backupFile)
                            if status == 0:
                                logger.info("Backup file has been compressed")
                                os.chmod(insert_backupFile + ".gz", 0640)

                        except Exception, e:
                            logger.error("Error writting backup file :%s" % str(e))
                            return
                        firstEventDateTime = firstEventDateTime + timedelta(days=1)
                except Exception, e:
                    logger.error("Error running the backup: %s" % str(e))

            self.__createDeleteBkFile()
            #
            # Deletes....
            #

            self.__deleteByBackupDays()
            self.__deleteByNumberOfEvents()
            self.__updateBackupConfigFile()


    def run(self):
        """ Entry point for the thread.
        """
        loop = 0
        while not self.__stopE.isSet():
            loop += 1
            # Reload configuration every 10 minutes
            if loop >= 20:
                logger.info("Reloading Backup Configuration")
                self.__loadConfiguration()
                loop = 0

            logger.info("BackupManager - Checking....")
            self.__run_backup()
            sleep(30)


    def stop(self):
        """Stop the current thread execution
        """
        self.__stopE.set()
