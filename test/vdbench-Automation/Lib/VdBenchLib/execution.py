# -*- coding: utf-8 -*-
#pylint : disable=E0401
"""
@author: SUSHANT KEDAR
DATACORE SOFTWARE PVT LTD CONFIDENTIAL
THIS SPEC IS THE PROPERTY OF DATACORE SOFTWARE PVT LTD.IT SHALL NOT BE
COPIED, USED,TRANSLATED OR TRANSFERRED IN WHOLE OR IN PART TO ANY THIRD
PARTY WITHOUT PRIOR WRITTEN PERMISSION OF DATACORE SOFTWARE PVT LTD.
File Name	:	test_file.py
Description	:	This script is going to call all Rest API of SSY
                as user want.

"""
import sys
import os
import json
import time
from os import path
import subprocess
from configparser import ConfigParser
from pywinauto.application import Application
sys.path.insert(0, os.path.abspath("../../../Interface/REST"))
from ILDC import ILDC
from Disks import Disks
sys.path.insert(0, os.path.abspath("../../../Lib/VdBenchLib"))
from error_log import LogCreat
from vdbench import VdBenchRun
class Test_ILDC:
    '''
    This class read user input of disk and workload
    and execute VdBench tool.
    Arguments : None
    Return: None
    '''
    pool_id = ''
    vdbench_path = ''
    server_id = ''
    def __init__(self):
        self.pd_ids = []
        self.config_dict = {}
        self.disk = []
        self.file = ''
        self.flag = 0
        self.co_disk = []
        self.disk_pool_disk = []
        self.test_status = ''
        self.vd_id = ''
        self.slog = []
        self.server_name = ''
        self.zfs_zvol = []
    def start(self):
        '''
        This method execute the test.
        Arguments : None
        Return: None
        '''
        time.sleep(10)
        self.get_host()
        self.get_server()
        flag = self.run()
        if flag == 0:
            self.execute_test()
        return flag
    def get_physical_disk_id(self):
        '''
        This method used to get all physical disk details.
        Arguments : None
        Return: None
        '''
        uri = "physicaldisks"
        pd_data = Disks().do_get_physical_disks(uri, header=None)
        pd_data = json.loads(pd_data.content)
        if len(pd_data) != 0:
            self.pd_ids = {x['DiskIndex']:x["Id"] for x in pd_data if x['Partitioned'] == False}
            msg = "Found %d physical disks in server group" % len(self.pd_ids)
            LogCreat().logger_info.info(msg)
        else:
            msg = "No Physical disks found"
            LogCreat().logger_error.error(msg)
        return self.pd_ids
    def read_config(self):
        '''
        This method read configuration file of VdBench.
        Arguments : None
        Return: None
        '''
        flag = 0
        configur = ConfigParser()
        configur.read(r"../../../Config/VdBench_config/VDBench_config.ini")
        self.config_dict['co disk'] = configur.get('Server level co', 's_disk').split(',')
        self.config_dict['diskpool_disk'] = configur.get('disk pool disk', 'd_disk').split(',')
        self.config_dict['slog_disk'] = configur.get('slog', 's_log_disk').split(',')
        self.disk = self.config_dict['co disk'] + self.config_dict['diskpool_disk'] + self.config_dict['slog_disk']
        self.config_dict['encryption_flag'] = configur.get('first run', 'enryption_flag')
        self.config_dict['slog_flag'] = configur.get('first run', 'slog_flag')
        self.config_dict['modify_flag'] = configur.get('first run', 'Modify_flag')
        if configur.get('first run', 'modify_flag').strip() == 'True':
            self.config_dict['primaycach'] = configur.get('zfs value', 'primarycache')
            self.config_dict['zfs_sync'] = configur.get('zfs value', 'sync')
            self.config_dict['zfs_compression'] = configur.get('zfs value', 'compression')
        if configur.get('first run', 'enryption_flag').strip() == 'True':
            self.encryption_setting('aes-256-gcm')
            LogCreat().logger_info.info('Encryption at zpool level set as aes-256-gcm')
        else:
            self.encryption_setting('none')
            LogCreat().logger_info.info('Encryption at zpool level set as None')
        if path.exists(configur.get('Vdbench run', 'vdbench_executable_path')) == False:
            flag = 1
            print("Invalid vdbench_executable_path set in configuration file")
            LogCreat().logger_error.error("Invalid vdbench_executable_path set in configuration file")
        if path.exists(configur.get('Vdbench run', 'python_path')) == False:
            flag = 1
            print("Invalid python_path set in configuration file")
            LogCreat().logger_error.error("Invalid python_path set in configuration file")
        if path.exists(configur.get('JRE path', 'jre_path')) == False:
            flag = 1
            print("Invalid JRE_path set in configuration file")
            LogCreat().logger_error.error("Invalid JRE_path set in configuration file")
        if path.exists(r"../../../Tools/External/ExpertMode/ExpertModePasswordGenerator.exe") is False:
            flag = 1
            print("Invalid Export mode path, keep Export mode exex to Tools/External/ExpertMode/ExpertModePasswordGenerator.exe")
            LogCreat().logger_error.error("Invalid Export mode path, keep Export mode exex to Tools/External/ExpertMode/ExpertModePasswordGenerator.exe")
        if flag == 0:
            flag = self.worklod_verify()
        return flag
    def worklod_verify(self):
        '''
        Verify all workload file are exist or not

        Returns
        -------
        flag : int
            flag = 0 passed
            flag = 1 failed

        '''
        flag = 0
        if path.exists(r"../../../Config/VdBench_config/Workload/4-4k-4-fill.vdb") is False:
            flag = 1
            print("Invalid 4k-4fill file. file should be in  Config/VdBench_config/Workload")
            LogCreat().logger_error.error("Invalid 4k-4fill file. file should be in  Config/VdBench_config/Workload")
        if path.exists(r"../../../Config/VdBench_config/Workload/oracle_fill.vdb") is False:
            flag = 1
            print("Invalid oracle_fill.vdb. file should be in  Config/VdBench_config/Workload")
            LogCreat().logger_error.error("Invalid oracle_fill.vdb file. file should be in  Config/VdBench_config/Workload")
        if path.exists(r"../../../Config/VdBench_config/Workload/sql_fill.vdb") is False:
            flag = 1
            print("Invalid sql_fill.vdb file. file should be in  Config/VdBench_config/Workload")
            LogCreat().logger_error.error("Invalid sql_fill.vdb file. file should be in  Config/VdBench_config/Workload")
        if path.exists(r"../../../Config/VdBench_config/Workload/vdi_fill.vdb") is False:
            flag = 1
            print("Invalid vdi_fill.vdb file. file should be in  Config/VdBench_config/Workload")
            LogCreat().logger_error.error("Invalid vdi_fill.vdb file. file should be in  Config/VdBench_config/Workload")
        if path.exists(r"../../../Config/VdBench_config/Workload/vsi_fill.vdb") is False:
            flag = 1
            print("Invalid vsi_fill.vdb file. file should be in  Config/VdBench_config/Workload")
            LogCreat().logger_error.error("Invalid vsi_fill.vdb. file should be in  Config/VdBench_config/Workload")
        return flag
    def extract_password(self):
        '''
        This function extract Exportmode password

        Returns
        -------
        password : str
            password of extract mode

        '''
        app = Application().start(
            r"../../../Tools/External/ExpertMode/ExpertModePasswordGenerator.exe")
        password = app.ExpertModePasswordGenerator.PasswordEdit.window_text()
        app.ExpertModePasswordGenerator.close()
        LogCreat().logger_info.info('ExpertMode password is extracted')
        return password
    def encryption_setting(self, algo):
        '''
        This function set encryption setting at zpool level

        Parameters
        ----------
        algo : str
            type of encryption enbale

        Returns
        -------
        None.

        '''
        password = self.extract_password()
        cmd = "powershell.exe -File \'C:/Program Files/DataCore/Powershell Support\Register-DcsCmdlets.ps1\'" + "\n"
        export_mode_cmd = 'Enable-DcsExpertMode -SecurityCode ' + password
        encry = 'set-dcsserverildcproperties -Server ' + self.server_name + ' -IldcEncryptionMode '+ algo
        process = subprocess.Popen(['powershell', cmd], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf8',
                                   universal_newlines=True, bufsize=0,
                                   creationflags=subprocess.CREATE_NEW_CONSOLE)
        process.stdin.write("connect-dcsserver" + "\n")
        process.stdin.write(export_mode_cmd + "\n")
        process.stdin.write(encry + "\n")
        process.stdin.close()
    def run(self):
        '''
        This method validate disk is used by othere process.
        If its used by othere process it will raise error and
        stop execution of tool.
        Arguments : None
        Return (int): flag
        '''
        flag = 0
        flag = self.read_config()
        time.sleep(120)
        pd_ids = self.get_physical_disk_id()
        for _ in self.disk:
            ILDC().clean_diskpart(_)
            if int(_) not in pd_ids.keys():
                msg = 'Disk index '+str(_)+ ' Already used by other process'
                print(msg)
                LogCreat().logger_error.error(msg)
                flag = 1
            else:
                if _ in self.config_dict['co disk']:
                    self.co_disk.append(pd_ids[int(_)])
                elif _ in self.config_dict['diskpool_disk']:
                    self.disk_pool_disk.append(pd_ids[int(_)])
                else:
                    self.slog.append(pd_ids[int(_)])
                self.release_disk(pd_ids[int(_)])
                time.sleep(1)
        return flag
    def custom_setting(self):
        '''
        This function used to get zpool nd zvol details

        Returns
        -------
        flag : int
            This flag verify operation is sucessful or not
            flag= 0 pass
            flag = 1 failed

        '''
        flag = 0
        process = subprocess.Popen('cmd.exe', stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf8',
                                   universal_newlines=True, bufsize=0,
                                   creationflags=subprocess.CREATE_NEW_CONSOLE, shell=False)
        process.stdin.write('cd /d c:\\' + "\n")
        process.stdin.write("cd \"C:/Program Files/DataCore/SANsymphony/zfs\"" + "\n")
        process.stdin.write("zfs list" + "\n")
        process.stdin.close()
        output = process.stdout.read().split('\n')
        if len(output) == 15:
            for _ in output[9:13]:
                self.zfs_zvol.append(_.split()[0])
            flag = self.set_modification()
        else:
            LogCreat().logger_error.error("Failed to get ZVOL's")
            flag = 1
        return flag
    def set_primarycache(self):
        '''
        set primarycache

        Returns
        -------
        flag : int
        This flag verify operation is sucessful or not
        flag= 0 pass
        flag = 1 failed

        '''
        flag = 0
        if self.config_dict['primaycach'].lower() != 'default':
            process = subprocess.Popen('cmd.exe', stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf8',
                                       universal_newlines=True, bufsize=0,
                                       creationflags=subprocess.CREATE_NEW_CONSOLE, shell=False)
            process.stdin.write('cd /d c:\\' + "\n")
            process.stdin.write("cd \"C:/Program Files/DataCore/SANsymphony/zfs\"" + "\n")
            
            cmd = 'zfs set primarycache=' + self.config_dict['primaycach'].lower() + ' '+ self.zfs_zvol[0]
            process.stdin.write(cmd + "\n")
            process.stdin.write("zfs get primarycache" + "\n")
            process.stdin.close()
            output = process.stdout.read().split('\n')
            if output[11].split()[2] != self.config_dict['primaycach'].lower():
                LogCreat().logger_error.error('Failed to set primarycache')
                flag = 1
            else:
                LogCreat().logger_info.info('zfs primarycache set to the ' + self.config_dict['primaycach'].lower())
        return flag
    def set_sync(self):
        '''
        Set sync file

        Returns
        -------
        flag : int
            This flag verify operation is sucessful or not
            flag= 0 pass
            flag = 1 failed

        '''
        flag = 0
        if self.config_dict['zfs_sync'].lower() != 'default':
            process = subprocess.Popen('cmd.exe', stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf8',
                                       universal_newlines=True, bufsize=0,
                                       creationflags=subprocess.CREATE_NEW_CONSOLE, shell=False)
            process.stdin.write('cd /d c:\\' + "\n")
            process.stdin.write("cd \"C:/Program Files/DataCore/SANsymphony/zfs\"" + "\n")
            cmd = 'zfs set sync=' + self.config_dict['zfs_sync'].lower() + ' '+ self.zfs_zvol[1]
            process.stdin.write(cmd + "\n")
            cmd = 'zfs set sync=' + self.config_dict['zfs_sync'].lower() + ' '+ self.zfs_zvol[2]
            process.stdin.write(cmd + "\n")
            cmd = 'zfs set sync=' + self.config_dict['zfs_sync'].lower() + ' '+ self.zfs_zvol[3]
            process.stdin.write(cmd + "\n")
            process.stdin.write("zfs get sync" + "\n")
            process.stdin.close()
            output = process.stdout.read().split('\n')
            if output[17].split()[2] != self.config_dict['zfs_sync'].lower():
                LogCreat().logger_error.error('Failed to zfs sync')
                flag = 1
            else:
                LogCreat().logger_info.info('zfs sync set to the '+ self.config_dict['zfs_sync'].lower())
        return flag
    def set_modification(self):
        '''
        This method set custom value like compression/sync/primarycache

        Returns
        -------
        flag : int
            This flag verify operation is sucessful or not
            flag= 0 pass
            flag = 1 failed

        '''

        flag = 0
        if self.config_dict['zfs_compression'].lower() != 'default':
            process = subprocess.Popen('cmd.exe', stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf8',
                                       universal_newlines=True, bufsize=0,
                                       creationflags=subprocess.CREATE_NEW_CONSOLE, shell=False)
            process.stdin.write('cd /d c:\\' + "\n")
            process.stdin.write("cd \"C:/Program Files/DataCore/SANsymphony/zfs\"" + "\n")
            
            cmd = 'zfs set compression=' + self.config_dict['zfs_compression'].lower() + ' '+ self.zfs_zvol[1]
            process.stdin.write(cmd + "\n")
            cmd = 'zfs set compression=' + self.config_dict['zfs_compression'].lower() + ' '+ self.zfs_zvol[2]
            process.stdin.write(cmd + "\n")
            cmd = 'zfs set compression=' + self.config_dict['zfs_compression'].lower() + ' '+ self.zfs_zvol[3]
            process.stdin.write(cmd + "\n")
            process.stdin.write("zfs get compression" + "\n")
            process.stdin.close()
            output = process.stdout.read().split('\n')
            if output[17].split()[2] != self.config_dict['zfs_compression'].lower():
                LogCreat().logger_error.error('Failed to set compression')
                flag = 1
            else:
                LogCreat().logger_info.info('zfs compression set to the '+ self.config_dict['zfs_compression'].lower())
        if flag == 0:
            flag = self.set_sync()
            if flag == 0:
                flag = self.set_primarycache()
        return flag
    def release_disk(self, disk):
        '''
        This function release disk to OS

        Parameters
        ----------
        disk : str
            this is disk id which used to release disk

        Returns
        -------
        None.

        '''
        uri = "physicaldisks/" + disk
        ILDC().do_enable_capacity_optimization(uri, header=None, payload=None)
    def set_slog(self):
        '''
        This method set SLOG 

        Returns
        -------
        None.

        '''
        process = subprocess.Popen('cmd.exe', stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf8',
                                   universal_newlines=True, bufsize=0,
                                   creationflags=subprocess.CREATE_NEW_CONSOLE, shell=False)
        process.stdin.write('cd /d c:\\' + "\n")
        process.stdin.write("cd \"C:/Program Files/DataCore/SANsymphony/zfs\"" + "\n")
        process.stdin.write("zfs list" + "\n")
        process.stdin.close()
        output = process.stdout.read().split('\n')
        
        out = output[9].split()[0]
        drive = ''
        for id_ in self.config_dict['slog_disk']:
            drive = drive + ' ' +'PHYSICALDRIVE' + str(id_) + ' '
        cmd_ = 'zpool add ' + out + ' log ' + drive.strip()
        self.call_log(cmd_)
    def call_log(self, cmd_):
        '''
        This method create command for SLOG setting

        Parameters
        ----------
        cmd_ : str
            extract zpool from zfs list

        Returns
        -------
        None.

        '''
        process = subprocess.Popen('cmd.exe', stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf8',
                                   universal_newlines=True, bufsize=0,
                                   creationflags=subprocess.CREATE_NEW_CONSOLE, shell=False)
        process.stdin.write('cd /d c:\\' + "\n")
        process.stdin.write("cd \"C:/Program Files/DataCore/SANsymphony/zfs\"" + "\n")
        process.stdin.write(cmd_ + "\n")
        process.stdin.close()
        output = process.stdout.read().split('\n')
        LogCreat().logger_info.info('SLOG is Enabled')
    def input_for_test(self):
        '''
        This method pass disk and workload details to the tool.
        Returns
        -------
        vd_name : str
            virtual disk type
        workload : str
            type of workload
        flag_run : int
            operational flag which tell operation status
            flag_run = 0 pass
            flag_run = 1 failed
        '''
        flag_run = 0
        vd_name = ''
        workload = ''
        self.file = open(r"../../../Config/Test.txt", "r+")
        data = self.file.readlines()
        self.file.close()
        if data == []:
            msg = 'There is nothing to perform please pass arguments to continue process'
            LogCreat().logger_info.info(msg)
        else:
            virtual_disk = data[0].split()
            vd_name = virtual_disk[0]
            workload = virtual_disk[1]
            flag_run = 1
            file = open(r"../../../Config/Test.txt", "w+")
            for _ in data[1:]:
                file.write(_)
            file.close()
        return vd_name, workload, flag_run
    def execute_test(self):
        '''
        This method execute workload and create all required
        configuration of SSY.
        Arguments : None
        Return: None
        '''
        flag = 0
        flag_ = 0
        vd_name, workload, flag_run = self.input_for_test()
        if flag_run == 1:
            print('************************'\
                  'Test Started************************\n')
            LogCreat().logger_info.info('************************'\
                                        'Test Started************************')
            time.sleep(30)
            if vd_name.lower() != "standard":
                flag = self.test_enable_cap_opt_at_server()
                if self.config_dict['slog_flag'] == 'True':
                    time.sleep(10)
                    self.set_slog()
            if flag == 0:
                time.sleep(15)
                self.create_diskpool(vd_name)
                if vd_name.lower() != "standard":
                    if self.config_dict['modify_flag'] == 'True':
                        flag_ = self.custom_setting()
                        time.sleep(10)
                if flag_ == 0:
                    time.sleep(25)
                    self.stop_server()
                    time.sleep(25)
                    self.start_server()
                    time.sleep(25)
                    self.test_create_virtual_disk(vd_name)
                    time.sleep(25)
                    self.set_vd_properties(vd_name)
                    time.sleep(25)
                    self.test_serve_vd_to_host()
                    time.sleep(25)
                    diskindex = self.initialize_vd()
                    time.sleep(25)
                    print('************************'\
                          'VdBench Execution Started************************\n')
                    LogCreat().logger_info.info('************************'\
                                                'VdBench Execution Started************************')
                    VdBenchRun().run(vd_name, workload, diskindex)
                    print('Result creation completed')
                    print('************************'\
                          'Setup Cleanup Started************************\n')
                    LogCreat().logger_info.info('************************'\
                                                'Setup Cleanup Started************************')
                    self.un_server_vd()
                    time.sleep(25)
                    self.delete_vd()
                    time.sleep(25)
                self.delete_pool()
                time.sleep(120)
            if vd_name.lower() != "standard":
                self.test_disable_cap_opt_at_server()
                time.sleep(180)
            print('************************'\
                  'VdBench Execution Completed************************\n')
            LogCreat().logger_info.info('************************'\
                                        'VdBench Execution Completed************************')
    def verification(self, res_json, msg):
        '''
        This method used to log INFO and ERROR to log file.
        Arguments (dict, str): res_json, msg
        Return (str): flag
        '''
        flag = 0
        try:
            if 'ErrorCode' not in res_json.keys():
                self.test_status = "Pass"
                LogCreat().logger_info.info(msg)
                print(msg)
            else:
                self.test_status = "Fail"
                print(res_json['Message'])
                flag = 1
                LogCreat().logger_error.error(res_json['Message'])
        except:
            LogCreat().logger_error.error(res_json['Message'])
            flag = 1
        return flag
    def test_enable_cap_opt_at_server(self):
        '''
        This method Enable capacity optimization at server level.
        Arguments : None
        Return: None
        '''
        uri = "servers/" + self.server_id
        payload_dict = {
            "Operation": "EnableCapacityOptimization",
            "Disks": self.co_disk,
        }
        res = ILDC().do_enable_capacity_optimization(uri, header=None, payload=payload_dict)
        msg = "Capacity Optimization enabled successfully at server"
        flag = self.verification(res.json(), msg)
        return flag
    def create_diskpool(self, vd_name):
        '''
        This method create diskpool.
        Arguments : None
        Return: None
        '''
        uri = "pools"
        payload_dict = {
            "Name": "diskpool 1",
            "Server": self.server_id,
            "Disks": self.disk_pool_disk[0:1]
        }
        if vd_name.lower() != "standard":
            payload_dict["Deduplication"] = "True"
        res = ILDC().do_create_pool(uri, header=None, payload=payload_dict)
        msg = "Diskpool created successfully with capacity optimization"
        time.sleep(2)
        self.verification(res.json(), msg)
        self.pool_id = res.json()['Id']
        if len(self.disk_pool_disk) > 1:
            self.add_disk_to_pool()
            
        msg="Reclamation started..."
        print(msg)
        LogCreat().logger_info.info(msg)
        
        time.sleep(15)
        while (self.reclamation() == False):
            print(".", sep='', end='', flush=True)
            time.sleep(15)
        print("\n")
        msg="Reclamation completed"
        print(msg)
        LogCreat().logger_info.info(msg)
            
    def add_disk_to_pool(self):
        '''
        This method add disks to diskpool.
        Arguments : None
        Return: None
        '''
        uri = "pools/" + self.pool_id
        payload_dict = {
            "Operation": "AddDisks",
            "Disks": self.disk_pool_disk[1:]
        }
        res = ILDC().do_create_pool(uri, header=None, payload=payload_dict)
        msg = "Disks are added to Diskpool"
        if str(res) == '<Response [200]>':
            LogCreat().logger_info.info(msg)
        else:
            self.verification(res.json(), msg)
    def reclamation(self):
        '''
        This method verify reclamation of diskpool.
        Arguments : None
        Return (int): self.flag
        '''
        uri = "performancebytype/DiskPoolPerformance"
        res = ILDC().do_ssy_details(uri, header=None)
        if res.json() != []:
            for _ in res.json():
                for key, val in _.items():
                    if key == 'PerformanceData' and val["BytesInReclamation"] == 0:
                        return True
        return False
    def get_server(self):
        '''
        This method used to get server details.
        Arguments : None
        Return: None
        '''
        uri = "servers"
        res = ILDC().do_ssy_details(uri, header=None)
        self.server_id = res.json()[0]['Id']
        self.server_name = res.json()[0]['HostName']
        msg = 'Get server details'
        if str(res) == '<Response [200]>':
            LogCreat().logger_info.info(msg)
        else:
            self.verification(res.json(), msg)
    def get_host(self):
        '''
        This method used to get host details.
        Arguments : None
        Return: None
        '''
        uri = 'hosts'
        res = ILDC().do_ssy_details(uri, header=None)
        msg = 'Get host details'
        if str(res) == '<Response [200]>':
            LogCreat().logger_info.info(msg)
        else:
            self.verification(res.json(), msg)
    def test_disable_cap_opt_at_server(self):
        '''
        This method used to disable capacity optimization at
        server level.
        Arguments : None
        Return: None
        '''
        uri = "servers/" + self.server_id
        payload_dict = {
            "Operation": "RemoveCapacityOptimizationDisks",
            "Disks": self.co_disk,
        }
        res = ILDC().do_disable_capacity_optimization(uri, header=None, payload=payload_dict)
        msg = "Capacity Optimization disabled successfully at server"
        self.verification(res.json(), msg)
    def delete_pool(self):
        '''
        This method used to delete diskpool.
        Arguments : None
        Return: None
        '''
        uri = "pools/" + self.pool_id
        res = ILDC().do_pool_delete(uri)
        msg = "Diskpool deleted successfully"
        if str(res) == '<Response [200]>':
            print(msg)
            LogCreat().logger_info.info(msg)
        else:
            self.verification(res.json(), msg)
    def test_create_virtual_disk(self, virtual_disk):
        '''
        This method used to create Virtual disk.
        Arguments (str): virtual disk
        Return: None
        '''
        uri = "virtualdisks"
        vd_payload = {
            "Name": virtual_disk+"_VD",
            "Description": "Description of virtual disk",
            "Size": "500GB",
            "SectorSize": "512B",
            "PoolVolumeType": "0",  # 0-stripped, 1-spanned,
            "Pool":self.pool_id,
            "Type": "0",
            "Count": "1",
        }
        res = ILDC().do_create_vd(uri, header=None, payload=vd_payload)
        msg = "Virtual disk created successfully"
        if str(res) == '<Response [200]>':
            print(msg)
            LogCreat().logger_info.info(msg)
        else:
            self.verification(json.loads(res.content), msg)
        res = json.loads(res.content)
        if len(res) != 0:
            vd_id = [x["Id"] for x in res]
            self.vd_id = vd_id[0]
    def set_vd_properties(self, virtual_disk):
        '''
        This method used to set virtual disk property.
        Arguments (str): virtual disk
        Return: None
        '''
        payload = {}
        #Once the VD is created set virtual disk properties
        if virtual_disk.lower() != "standard":
            if virtual_disk.lower().strip() == "ildc":

                payload["Deduplication"] = True
                payload["Compression"] = True
            elif virtual_disk.lower() == "ild":
                payload["Deduplication"] = True
            elif virtual_disk.lower() == "ilc":
                payload["Compression"] = True
            uri = "virtualdisks/" + self.vd_id
            res = ILDC().do_enable_cap_opt_on_vd(uri, header=None, payload=payload)
            msg = virtual_disk + " properties enabled successfully on virtual disk"
            if str(res) == '<Response [200]>':
                print(msg)
                LogCreat().logger_info.info(msg)
            else:
                self.verification(res.json(), msg)
        else:
            if self.config_dict['encryption_flag'] == 'True':
                payload["EncryptionEnabled"] = True
                uri = "virtualdisks/" + self.vd_id
                res = ILDC().do_enable_cap_opt_on_vd(uri, header=None, payload=payload)
                msg = virtual_disk + " property enable at virtual disk level"
                if str(res) == '<Response [200]>':
                    print(msg)
                    LogCreat().logger_info.info(msg)
                else:
                    self.verification(res.json(), msg)
    def test_serve_vd_to_host(self):
        '''
        This method used serve virtual disk to host.
        Arguments : None
        Return: None
        '''
        uri = "virtualdisks/" + self.vd_id
        serve_payload = {
            "Operation": "Serve",
            "Host": self.server_id,
            "Redundancy": "false"
        }
        res = ILDC().do_serve_vd(uri, header=None, payload=serve_payload)
        msg = "Virtual disk successfully served to the host"
        if str(res) == '<Response [200]>':
            print(msg)
            LogCreat().logger_info.info(msg)
        else:
            self.verification(res, msg)
    def un_server_vd(self):
        '''
        This method used to unserve virtual disk from host.
        Arguments : None
        Return: None
        '''
        uri = "virtualdisks/" + self.vd_id
        payload_dict = {
            "Operation": "Unserve",
            "Host": self.server_id
        }
        res = ILDC().do_serve_vd(uri, header=None, payload=payload_dict)
        msg = "Virtual disk unserved successfully"
        if str(res) == '<Response [200]>':
            print(msg)
            LogCreat().logger_info.info(msg)
        else:
            self.verification(res.json(), msg)
    def delete_vd(self):
        '''
        This method used to delete virtual disk.
        Arguments : None
        Return: None
        '''
        uri = "virtualdisks/" + self.vd_id
        res = ILDC().do_vd_delete(uri)
        msg = "Virtual disk deleted successfully"
        if str(res) == '<Response [200]>':
            print(msg)
            LogCreat().logger_info.info(msg)
        else:
            self.verification(res.json(), msg)
    def stop_server(self):
        '''
        This method used to stop server.
        Arguments : None
        Return: None
        '''
        uri = "servers/" + self.server_id
        payload_dict = {
            "Operation" : "StopServer"
        }

        res = ILDC().do_serve_on_off(uri, header=None, payload=payload_dict)
        msg = "Server stopped successfully"
        self.verification(res.json(), msg)
    def start_server(self):
        '''
        This method used to start server.
        Arguments : None
        Return: None
        '''
        uri = "servers/" + self.server_id
        payload_dict = {
            "Operation": "StartServer"
        }
        res = ILDC().do_serve_on_off(uri, header=None, payload=payload_dict)
        msg = "Server started successfully"
        test_status = self.verification(res.json(), msg)
        return test_status
    def initialize_vd(self):
        '''
        This method used to initialize virtual disk.
        Arguments : None
        Return: None
        '''
        uri = "physicaldisks"
        pd_data = Disks().do_get_physical_disks(uri, header=None)
        pd_data = json.loads(pd_data.content)
        for i in range(len(pd_data)):
            for key, val in pd_data[i].items():
                if key == "VirtualDiskId" and val in self.vd_id:
                    diskindex = pd_data[i]['DiskIndex']
                    ILDC().initial_disk(diskindex)
                    msg = "Initialized virtual disk successfully"
                    print(msg)
                    LogCreat().logger_info.info(msg)
                    break
        return diskindex
               