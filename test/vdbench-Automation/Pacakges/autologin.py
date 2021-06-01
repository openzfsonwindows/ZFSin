# -*- coding: utf-8 -*-
#pylint : disable=E0401
"""
@author: SUSHANT KEDAR
DATACORE SOFTWARE PVT LTD CONFIDENTIAL
THIS SPEC IS THE PROPERTY OF DATACORE SOFTWARE PVT LTD.IT SHALL NOT BE
COPIED, USED,TRANSLATED OR TRANSFERRED IN WHOLE OR IN PART TO ANY THIRD
PARTY WITHOUT PRIOR WRITTEN PERMISSION OF DATACORE SOFTWARE PVT LTD.
File Name	:	autologin.py
Description	:	This script used buy pass system password login after restart.

"""
import os
import time
import subprocess
import configparser
from configparser import ConfigParser
import winapps
class AutoLoggin():
    '''
    This script used buy pass system password login after restart.
    '''
    def __init__(self):
        self.config_path = r'..\..\..\Config\VdBench_config\VDBench_config.ini'
        self.file_path = ''
        self.data = ''
        self.file = ''
    def config_read(self, section, key_list):
        '''
        This method read config file perticular section.
        Arguments (str, str): section,key_list
        Return (str): output

        Parameters
        ----------
        section : str
            It is section of configuration file
        key_list : str
            It is key of configuration file
        Returns
        -------
        output : str
            value of respective key
        '''
        parser = configparser.ConfigParser()
        parser.read(self.config_path)
        output = ''
        for sect in parser.sections():
            if sect.strip() == section:
                for key, val in parser.items(sect):
                    if key.strip() == key_list:
                        output = val
                        break
        return output
    def autolog_reg_set(self):
        '''
        This method is going to add regestry which required for autologin
        please go through this:-https://docs.microsoft.com/en-us/troubleshoot/
        windows-server/user-profiles-and-logon/turn-on-automatic-logon
        Arguments : None
        Return (int): flag
                    it confirm registry is set or not
        '''
        reg_list = []
        flag = 0
        system_id = self.config_read('system login', 'user_id')
        system_pass = self.config_read('system login', 'pass')
        status = self.config_read('first run', 'run')
        if status == 'False':
            if system_id != '' and system_pass != '':
                add_key = 'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" '
                flag = 1
                str_ = add_key + '/v DefaultUserName /t REG_SZ /d ' + system_id + ' /f'
                reg_list.append(str_)
                str_ = add_key + '/v DefaultPassword /t REG_SZ /d ' + system_pass + ' /f'
                reg_list.append(str_)
                str_ = add_key + '/v AutoAdminLogon /t REG_SZ /d 1 /f'
                reg_list.append(str_)
                self.bat_run(reg_list)
        return flag
    def bat_run(self, reg_list):
        '''
        This method is going to create Team bat file which set all registery
        Parameters
        ----------
        reg_list : list
            this list consist all registry which is going to write in bat file

        Returns
        -------
        None.

        '''
        self.file = open('Temp.bat', "w")
        for str_ in reg_list:
            self.file.write(str_ + '\n')
        self.file.close()
        os.system('Temp.bat')
        os.remove('Temp.bat')
    def run(self):
        '''
        This method will callall required method to verify software are available or not
        to conduct vdbench experiment.
        Returns
        -------
        flag : int
            this flag indicate execution conditions
            if flag = 0 
            all opration pass
            if flag = 1
            operation failed
        msg : str
            consiste error msg if flag = 1 
        '''
        print('******************Autologin setting is in progress******************')
        self.data = ''
        msg = ''
        verify_flag, jre_flag = self.verify_software()
        if verify_flag == 1:
            flag = self.reg_sheduler_bat()
            if jre_flag == 1:
                print('System will restart in 30 sec')
                time.sleep(30)
                os.system("shutdown /r /t 1")
        else:
            msg = 'JRE path section is missing from VdBench_config file'
            print(msg)
        return flag, msg
    def reg_sheduler_bat(self):
        '''
        This method call bat file for vdbech will alway kick after every restart
        Returns
        -------
        flag : int
            it verify registry s set or not
        '''
        file_name = os.path.abspath('') + '\\'+'TestSuite.py'
        path = self.create_batfile(file_name)
        new_key = 'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" '\
            '/v vdbench_run /t REG_SZ /d '+path+' /f'
        default_cmd = 'reg add '\
            '"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" '\
            '/v C:\Windows\System32\cmd.exe /t REG_SZ /d RUNASADMIN /f'
        self.bat_run([new_key, default_cmd])
        flag = self.autolog_reg_set()
        return flag
    def verify_jre(self):
        '''
        This method verify JRE install or not
        Returns
        -------
        flag : int
            this flag check JRE is istalled or not if it is not installed
            it will install it
        jre_flag : int
            this flag make flag as 1 if JRE is installed
        '''
        path = self.config_read('JRE path', 'jre_path')
        flag = 0
        jre_flag = 0
        if path != '':
            data = subprocess.check_output(['wmic', 'product', 'get', 'name'])
            aout = str(data)
            try:
                list_ = aout.split("\\r\\r\\n")
                for soft in list_:
                    if len(soft.split()) == 5:
                        if 'Java' in str(soft) and 'Update' in str(soft) and str(
                                soft.strip()) != 'Java Auto Updater':
                            flag = 1
                            break
            except IndexError:
                pass
            if flag == 0:
                str_ = 'start /w ' + path+ ' /s'
                os.system(str_)
                flag = 1
                jre_flag = 1
        return flag, jre_flag
    def verify_software(self):
        '''
        This method verify SSY is install or not
        Returns
        -------
        verify_flag : int
            This flag indicate SSY is installed or not
            0 = not installed
            1 = installed
        jre_flag : int
            This flag indicate JRE is installed or not
            0 = not installed
            1 = installed
        '''
        verify_flag = 0
        install_flag = 0
        for item in winapps.search_installed('DataCore SANsymphony'):
            install_flag = 1
            del item
        if install_flag == 1:
            flag, jre_flag = self.verify_jre()
            if flag == 1:
                verify_flag = 1
        return verify_flag, jre_flag
    def create_batfile(self, file_name):
        '''
        This method create dynamic bat file fo sheduler
        Parameters
        ----------
        file_name : str
            file path where we have to save bat file

        Returns
        -------
        ab_path = str
        absolute path of bat file to set registry
        '''
        self.file_path = "VdBench.bat"
        python_path = self.config_read('Vdbench run', 'python_path')
        file = open(self.file_path, "w")
        if os.path.abspath('').split(':')[0].lower() != 'c':
            str_ = 'cd /d '+os.path.abspath('').split(':')[0].lower()+':\\'
            file.write(str_ + '\n')
        file.write('cd '+os.path.abspath('')+ '\n')
        file.write(python_path + ' ' + file_name+'\n')
        file.write('pause' + '\n')
        file.close()
        ab_path = os.path.abspath('') + '\\'+self.file_path
        return ab_path
    def del_sub_sheduler(self):
        '''
        This method delete bat file fo sheduler
        Arguments : None
        Return: None
        '''
        reg = 'reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v vdbench_run /f'
        self.bat_run([reg])
    def set_config_val(self, section, key, val):
        '''
        This function overwrite value of config file by seraching section and key

        Parameters
        ----------
        section : str
            config file haveing section and each section having own key and
            value pair
        key : str
            key is part of section and it is unique value
        val : str
            val is value of respective key

        Returns
        -------
        None.

        '''
        configur = ConfigParser()
        configur.read(self.config_path)
        configur.set(section, key, val)
        with open(self.config_path, 'w') as configfile:
            configur.write(configfile)
