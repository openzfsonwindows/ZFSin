# -*- coding: utf-8 -*-
#pylint : disable=E0401
"""
@author: SUSHANT KEDAR
DATACORE SOFTWARE PVT LTD CONFIDENTIAL
THIS SPEC IS THE PROPERTY OF DATACORE SOFTWARE PVT LTD.IT SHALL NOT BE
COPIED, USED,TRANSLATED OR TRANSFERRED IN WHOLE OR IN PART TO ANY THIRD
PARTY WITHOUT PRIOR WRITTEN PERMISSION OF DATACORE SOFTWARE PVT LTD.
File Name	:	run_vdbench.py
Description	:	This script is main script which validate pre-requesites.

"""
import os
import argparse
import time
from os import path
import sys
import datetime
import os.path
sys.path.insert(0, os.path.abspath("../../../Lib/VdBenchLib"))
from execution import Test_ILDC
from error_log import LogCreat
from configparser import ConfigParser
sys.path.insert(0, os.path.abspath("../../../Pacakges"))
from autologin import AutoLoggin
class Run():
    '''
    This method main run script.
    '''
    def __init__(self):
        self.config_file = r"../../../Config/VdBench_config/VDBench_config.ini"
        self.config_test = r"../../../Config/Test.txt"
        self.list_lines = []
        self.file = ''
        configur = ConfigParser()
        configur.read(self.config_file)
        flag = 1
        msg = ''
        flag_ = self.verification_file()
        if configur.get('first run', 'run') == 'False':
            today = datetime.datetime.now()
            date_time = today.strftime("%y-%m-%d_%H-%M-%S")
            self.set_config_val('first run', 'start', date_time)
            flag, msg = AutoLoggin().run()
        if flag_ == 0 and flag == 1 and msg == '':
            self.arguments()
        else:
            if msg != '':
                LogCreat().logger_error.error(msg)
            else:
                flag = Test_ILDC().start()
                if flag == 0:
                    self.set_config_val('first run', 'run', 'True')
                    print('System will restart in 30 sec')
                    time.sleep(30)
                    os.system("shutdown /r /t 1")
                else:
                    self.reset_config()
                    AutoLoggin().del_sub_sheduler()
                    self.remove_test_file()
    def remove_test_file(self):
        '''
        This function deleted sheduler bat file once execution completed.
        Returns
        -------
        None.
        '''
        if path.exists(self.config_test) is True:
            os.remove(self.config_test)
        path_ = os.path.abspath("") + '/' + "VdBench.bat"
        if path.exists(path_) is True:
            os.remove(path_)
    def set_config_val(self, section, key, val):
        '''
        This function overwrite value of key of configuration file.
        Parameters
        ----------
        section : str
            It is section of configuration file
        key : str
            It is key of configuration file
        val : str
            It is val of configuration file

        Returns
        -------
        None.

        '''
        configur = ConfigParser()
        configur.read(self.config_file)
        configur.set(section, key, val)
        with open(self.config_file, 'w') as configfile:
            configur.write(configfile)
    def config_creation(self, args):
        '''
        This method read user args and create hidden config for
        workload execution.
        Parameters
        ----------
        args : obj
            It is argument given by the user

        Returns
        -------
        None.

        '''
        load = args.workload
        disk = args.disktype
        all_disk = ['ILDC', 'ILD', 'ILC', 'STANDARD']
        all_load = ['VSI', 'VDI', 'SQL', 'ORACLE']
        self.list_lines = []
        if disk.lower().strip() == 'all' and load.lower().strip() == 'all':
            for _ in all_disk:
                for j in all_load:
                    str_ = _.upper() + ' ' + j.upper()
                    self.list_lines.append(str_)
        elif disk.lower().strip() == 'all' and load.lower().strip() != 'all':
            for _ in all_disk:
                str_ = _.upper() + ' ' + load.upper()
                self.list_lines.append(str_)
        elif disk.lower().strip() != 'all' and load.lower().strip() == 'all':
            for _ in all_load:
                str_ = disk.upper() + ' ' + _.upper()
                self.list_lines.append(str_)
        else:
            str_ = disk.upper() + ' ' + load.upper()
            self.list_lines.append(str_)
        with open(self.config_test, "w") as file:
            for item in self.list_lines:
                file.write("%s\n" % item)
            file.close()
    def verification_file(self):
        '''
        This method verify hidden config present or not.
        Arguments : None
        Return: None
        '''
        if path.exists(self.config_test) is True:
            self.file = open(self.config_test, "r+")
            data = self.file.readlines()
            self.file.close()
            if all(v == '\n' for v in data) is True:
                flag = 0
            else:
                flag = 1
        else:
            flag = 0
        return flag
    def arguments(self):
        '''
        This method take user inputs.
        Arguments : None
        Return: None
        '''
        configur = ConfigParser()
        configur.read(self.config_file)
        my_parser = argparse.ArgumentParser(description='Execute VD bench workloads')
        # Add the arguments
        my_parser.add_argument('-workload', '-w',
                               type=str,
                               help='Specify the workload to be executed.'\
                                   'Valid Values are : vsi,vdi,oracle,sql,all')
        my_parser.add_argument('-disktype', '-d',
                               type=str,
                               help='Specify the disk to be executed. '\
                                   'Valid Values are : ildc,ild,ilc,ssy,all')
        my_parser.add_argument('-slogselect', '-s',
                               type=str,
                               help='Specify the SLOG enable/disable '\
                                   'Valid Values are : on,off')
        my_parser.add_argument('-encryption', '-e',
                               type=str,
                               help='Specify the encryption enable/disable. '\
                                   'Valid Values are : on,off')
        my_parser.add_argument('-modify_zfs', '-m',
                       type=str,
                       help='Specify the parameter to be modified. '\
                           'Valid Values are : on,off')
        args = my_parser.parse_args()
        if args.modify_zfs == 'on':
            self.set_config_val('first run', 'modify_flag', 'True')
        else:
            self.set_config_val('first run', 'modify_flag', 'False')
        if args.encryption == 'on':
            self.set_config_val('first run', 'enryption_flag', 'True')
        else:
            self.set_config_val('first run', 'enryption_flag', 'False')
        if args.slogselect == 'on':
            self.set_config_val('first run', 'slog_flag', 'True')
        else:
            self.set_config_val('first run', 'slog_flag', 'False')
        if (args.workload is not None) and (args.disktype is not None):
            self.config_creation(args)
            flag = Test_ILDC().start()
            if flag == 0:
                file = open(self.config_test, "r+")
                data = file.readlines()
                file.close()
                if data != []:
                    self.set_config_val('first run', 'run', 'True')
                else:
                    self.reset_config()
                    AutoLoggin().del_sub_sheduler()
                    self.remove_test_file()
                print('System will restart in 30 sec')
                time.sleep(30)
                os.system("shutdown /r /t 1")
            else:
                self.reset_config()
                AutoLoggin().del_sub_sheduler()
                self.remove_test_file()
        else:
            print('Invalid arguments passed')
            self.reset_config()
            AutoLoggin().del_sub_sheduler()
            self.remove_test_file()
    def reset_config(self):
        '''
        reset config file

        Returns
        -------
        None.

        '''
        self.set_config_val('first run', 'run', 'False')
        self.set_config_val('first run', 'start', 'None')
        self.set_config_val('first run', 'slog_flag', 'False')
        self.set_config_val('first run', 'enryption_flag', 'False')
        self.set_config_val('first run', 'modify_flag', 'False')
        self.set_config_val('zfs value', 'primarycache', 'default')
        self.set_config_val('zfs value', 'sync', 'default')
        self.set_config_val('zfs value', 'compression', 'default')
if __name__ == "__main__":
    Run()
