# -*- coding: utf-8 -*-
#pylint : disable=E0401
"""
@author: SUSHANT KEDAR
DATACORE SOFTWARE PVT LTD CONFIDENTIAL
THIS SPEC IS THE PROPERTY OF DATACORE SOFTWARE PVT LTD.IT SHALL NOT BE
COPIED, USED,TRANSLATED OR TRANSFERRED IN WHOLE OR IN PART TO ANY THIRD
PARTY WITHOUT PRIOR WRITTEN PERMISSION OF DATACORE SOFTWARE PVT LTD.
File Name	:	vdbench.py
Description	:	This script used to execute vdbench tool and create
                HTML reports.

"""
import os
import sys
from configparser import ConfigParser
import subprocess
path_ = os.path.abspath("../../../Interface/REST")
sys.path.insert(0, path_)
from ILDC import ILDC
sys.path.insert(0, os.path.abspath("../../../Lib/VdBenchLib"))
from error_log import LogCreat

class VdBenchRun():
    '''
    Class:- VdBenchRun
    This class executes vdbench 4k fill and VSI/VDI/ORACLE/SQL
    wokload as user request.
    Arguments : None
    Return: None
    '''
    def __init__(self):
        configur = ConfigParser()
        configur.read(r"../../../Config/VdBench_config/VDBench_config.ini")
        self.vdbench_path = configur.get('Vdbench run', 'vdbench_executable_path')
        self.time_stamp = configur.get('first run', 'start')
        self.build = ''
        self.new_ = ''
        self.absulute = ''
    def run(self, vd_name, workload, diskindex):
        '''
        This method execute workload of VdBench tool.
        Parameters
        ----------
        vd_name : str
            store virtual disk name
        diskindex : str
            store virtual disk index
        workload : str
            store type of virtual disk
        Return: None
        '''
        workload_path, result_path = self.create_file('4-4k-4-fill.vdb',
                                                      vd_name, diskindex, workload)
        self.run_workload(workload_path, result_path, vd_name, workload)
        if workload.strip() == 'VDI':
            workload_path, result_path = self.create_file('vdi_fill.vdb',
                                                          vd_name, diskindex, workload)
        elif workload.strip() == 'VSI':
            workload_path, result_path = self.create_file('vsi_fill.vdb',
                                                          vd_name, diskindex, workload)
        elif workload.strip() == 'ORACLE':
            workload_path, result_path = self.create_file('oracle_fill.vdb',
                                                          vd_name, diskindex, workload)
        else:
            workload_path, result_path = self.create_file('sql_fill.vdb',
                                                          vd_name, diskindex, workload)
        self.run_workload(workload_path, result_path, vd_name, workload)

    def run_workload(self, workload_path, result_path, vd_name, workload):
        '''
        This method run workloads and stores the result

        Parameters
        ----------
        workload_path : str
            path where all vdbench workload config files are stored
        result_path : str
            store result path where need to store the vdbench results
        vd_name : str
            store virtual disk name

        workload : str
            store type of virtual disk

        Returns
        -------
        None.

        '''
        # Config\VdBench_config\Workload
        path = 'cd ' +  self.vdbench_path + '\n'
        str_ = 'vdbench -f "' + workload_path + '" -o "'+ result_path + '"' + "\n"
        ssh = subprocess.Popen(["cmd"],
                               stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               universal_newlines=True,
                               bufsize=0)
        # Send ssh commands to stdin
        ssh.stdin.write(path)
        ssh.stdin.write(str_)
        out, err = ssh.communicate()
        print(out, err)
        ssh.wait()
        if 'Vdbench execution completed successfully' in out:
            if '4-4k-4-fill' not in result_path:
                msg = workload.upper() + ' workload executed sucessfully'
                LogCreat().logger_info.info(msg)
                new_path = os.path.join(result_path, "flatfile.html")
                ResultCreation().read_result(new_path, vd_name, workload, self.new_)
            else:
                msg = '4-4k-4-fill workload executed sucessfully'
                LogCreat().logger_info.info(msg)
    def create_file(self, file_name, vd_name, diskindex, workload):
        '''
        This method create dynamic folder structure to store
        results of VdBench

        Parameters
        ----------
        file_name : str
            it store workload file path
        vd_name : str
            store virtual disk name
        diskindex : str
            store virtual disk index
        workload : str
            store type of virtual disk

        Returns
        -------
        workload_path : str
            store workload path
        result_path : str
            store result path where need to store the vdbench results

        '''
        uri = "servers"
        res = ILDC().do_ssy_details(uri, header=None)
        self.build = res.json()[0]['ProductBuild']
        workload_path = os.path.abspath(r'../../../Config/VdBench_config/Workload')
        self.absulute = os.path.abspath(r'../../../Result/Vdbench')
        self.new_ = self.absulute + '/' + self.build + '_' + self.time_stamp + '/'
        if file_name.split('.')[0] == '4-4k-4-fill':
            result_path = self.new_ + vd_name + '/' + workload + '_' + file_name.split('.')[0]
        else:
            result_path = self.new_ + vd_name+'/' + vd_name+'_' + file_name.split('.')[0]
        workload_path = os.path.join(workload_path, file_name)
        file = open(workload_path, "r+")
        data = file.readlines()
        file.close()
        for index, val in enumerate(data):
            split_ = val.split('PhysicalDrive')
            if len(split_) > 1:
                data[index] = split_[0] + "PhysicalDrive" + str(diskindex) + "\n"
        file = open(workload_path, "w")
        for _ in data:
            file.write(_)
        file.close()
        return workload_path, result_path

class ResultCreation():
    '''
    Class:- ResultCreation
    This class is going to collect VdBench result and store in
    HTML formate.
    Arguments : None
    Return: None
        '''
    glob_flag = 0
    data_put = []
    destiny = ''
    path = ''
    result_path = ''
    merge_list = []
    zfs_max = ''
    build = ''
    def get_server(self):
        '''
        This method collect all results of SSY required to update
        in HTML file

        Returns
        -------
        None.

        '''
        status_slog = 'OFF'
        status_encrp = 'OFF'
        configur = ConfigParser()
        configur.read(r"../../../Config/VdBench_config/VDBench_config.ini")
        print('check',configur.get('first run', 'slog_flag'), configur.get('first run', 'enryption_flag'))
        if configur.get('first run', 'slog_flag').strip() == 'True':
            status_slog = 'ON'
        if configur.get('first run', 'enryption_flag').strip() == 'True':
            status_encrp = 'ON'
        uri = "servers"
        res = ILDC().do_ssy_details(uri, header=None)
        self.build = res.json()[0]['ProductBuild']
        host = res.json()[0]['HostName']
        ram = res.json()[0]['TotalSystemMemory']['Value']
        ram_ = str(round(int(ram)/1073741824, 2))
        ram_ = ram_ + ' GB'
        # available = res.json()[0]['AvailableSystemMemory']['Value']
        sync = res.json()[0]['IldcConfigurationData']['IldcSyncMode']
        primaycach = res.json()[0]['IldcConfigurationData']['IldcPrimaryCacheMode']
        # ssy = int(ram) - int(available)
        # ssy = (round((ssy)/1073741824,2))
        # ssy = str(ssy) + ' GB'
        ssy = int(ram) * 0.65
        if self.merge_list[0] != '-':
            zfs = int(self.zfs_max)/1073741824
            ssy = int(round((ssy)/1073741824, 2))
            ssy = ssy - zfs
            zfs = str(round(zfs, 2))
            ssy = str(int(ssy)) + ' GB'
            zfs = zfs + ' GB'
        else:
            zfs = '-'
            ssy = str(int(ssy)) + ' GB'
        self.data_put = [self.build, host, str(zfs),
                         str(ssy), primaycach, ram_, sync, '500GB', status_slog , status_encrp]
    def run(self):
        '''
        This method create dynamic folder structure to store results

        Returns
        -------
        None.

        '''
        self.get_server()
        configur = ConfigParser()
        configur.read(r"../../../Config/VdBench_config/VDBench_config.ini")
        self.time_stamp = configur.get('first run', 'start')
        self.destiny = self.result_path + self.build + '.html'
        if configur.get('first run', 'run') == 'False':
            pat = os.path.abspath(r"../../../HTML_Template/VdBench_Template.html")
            self.path = pat
        else:
            pat = os.path.abspath(r"../../../Result/Vdbench")
            self.path = self.result_path + self.build + '.html'
        self.destiny = self.result_path + self.build + '.html'
    def read_result(self, new_path, vd_name, workload, result_path):
        '''
        This method read IOPS, Throughput and latency of workload

        Parameters
        ----------
        new_path : str
            path wehere hidden config is stored
        vd_name : str
            store name of virtual disk
        workload : str
            store type of workload
        result_path : str
            path where we have to store result

        Returns
        -------
        None.

        '''
        self.result_path = result_path
        file1 = open(new_path, "r+")
        list_lines = file1.readlines()
        list_data = [0, 0, 0]
        flag = 0
        for _ in list_lines:
            if _.split()[0] != '*':
                if flag == 1:
                    list_data[0] = str(round(float(_.split()[5])))
                    list_data[1] = str(round(float(_.split()[10]), 2))
                    list_data[2] = str(round(float(_.split()[6])))
                if _.split()[0] == 'tod':
                    flag = 1
        if vd_name.lower().strip() != 'standard':
            os_mem, ddt, comp, dedup = self.zfs_data()
            self.merge_list = [os_mem, ddt, dedup, comp, list_data[2], list_data[1], list_data[0]]
        else:
            self.merge_list = ['-', '-', '-', '-', list_data[2], list_data[1], list_data[0]]
            self.zfs_max = '-'
        self.start_update_html(vd_name, workload)
    def zfs_data(self):
        '''
        Thismethod read ZFS data.
        Arguments : None
        Return: None
        '''
        try:
            process = subprocess.Popen('cmd.exe', stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       encoding='utf8', universal_newlines=True, bufsize=0,
                                       creationflags=subprocess.CREATE_NEW_CONSOLE, shell=False)
            process.stdin.write('cd /d c:\\' + "\n")
            process.stdin.write("cd \"C:/Program Files/DataCore/SANsymphony/zfs\"" + "\n")
            process.stdin.write("zpool status -D" + "\n")
            process.stdin.write("kstat spl:0:spl_misc:os_mem_alloc" + "\n")
            process.stdin.write("zpool list" + "\n")
            process.stdin.write("zfs get compressratio" + "\n")
            process.stdin.write("kstat.exe zfs:0:tunable:zfs_arc_meta_limit" + "\n")
            process.stdin.write("kstat.exe zfs:0:tunable:zfs_arc_meta_limit" + "\n")
            process.stdin.write("zfs get primarycache" + "\n")
            process.stdin.write("zfs get sync" + "\n")
            process.stdin.close()
            output = process.stdout.read().split('\n')
            count = 0
            for _ in output:
                if count == 1:
                    count = 0
                    if 'compressratio' in _.split():
                        comp = str(_.split()[-2].strip('x'))
                    else:
                        dedup = str(_.split()[-3].strip('x'))
                if 'dedup: DDT entries' in _:
                    ddt = (int(_.split()[3].split(',')[0]))*(int(_.split()[8]))
                if 'os_mem_alloc' in _:
                    os_mem = _.split()[-1]
                if 'SIZE  ALLOC   FREE  CKPOINT' in _:
                    count = 1
                if 'PROPERTY       VALUE  SOURCE' in _:
                    count = 1
                if 'zfs_arc_meta_limit' in _:
                    self.zfs_max = _.split()[-1]
            ddt = str(round(ddt/1048576, 2))
            os_mem = str(round(int(os_mem)/1073741824, 2))
            return os_mem, ddt, comp, dedup
        except Exception as error:
            LogCreat().logger_error.error(error)
    def first_temp(self):
        '''
        This method update title of HTML page
        Arguments : None
        Return: None
        '''
        configur = ConfigParser()
        configur.read(r"../../../Config/VdBench_config/VDBench_config.ini")
        if configur.get('first run', 'run') == 'False':
            file1 = open(self.path, "r+")
            list_lines = file1.readlines()
            for index, val in enumerate(list_lines):
                if val.strip() == '<td class="u-align-center u-border-1 '\
                    'u-border-grey-dark-1 u-table-cell"></td>':
                    data_ = '<td class="u-align-center u-border-1 '\
                        'u-border-grey-dark-1 u-table-cell">' + str(self.data_put[0]) + '</td>'
                    list_lines[index] = data_
                    self.data_put.pop(0)
            with open(self.destiny, "w") as file:
                for item in list_lines:
                    file.write("%s\n" % item)
            file.close()
            self.path = self.destiny
            self.glob_flag = 1
    def start_update_html(self, virtualdisk, workload):
        '''
        This method append all results in HTML page
        Parameters
        ----------
        workload : str
            Type of workload
        virtualdisk : str
            Type of virtual disk (ILDC/ILC/ILD/STANDARD)
        Return: None
        '''
        path_html = os.path.abspath("../../..") + '/' + 'HTML_Template' + '/'
        self.run()
        if self.glob_flag == 0:
            self.first_temp()
        print('************************'\
              'VdBench Result Creation Started************************\n')
        LogCreat().logger_info.info('************************'\
                                    'VdBench Result Creation Started************************')
        update = '<td class="u-border-1 u-border-grey-30 u-table-cell u-table-cell-'
        file1 = open(self.path, "r+")
        list_lines = file1.readlines()
        number = self.update_lines(workload, virtualdisk)
        for index, val in enumerate(list_lines):
            vsi_new = update + str(number)
            if vsi_new in val.strip():
                data = '<td class="u-border-1 u-border-grey-30'\
                    ' u-table-cell u-table-cell-' + str(number)
                data = data + '">' + self.merge_list[0] + "</td>"
                list_lines[index] = data
                self.merge_list.pop(0)
                number += 5
            if val.strip() == '<script class="u-script" type="text/javascript" '\
                'src="jquery.js" defer=""></script>':
                list_lines[index] = '<script class="u-script" type="text/javascript" '\
                    'src=""' + path_html + 'jquery.js" defer=""></script>'
            if val.strip() == '<link rel="stylesheet" href="nicepage.css" media="screen">':
                list_lines[index] = '<link rel="stylesheet" '\
                    'href="' + path_html+'nicepage.css" media="screen">'
            if val.strip() == '<link rel="stylesheet" href="VdBench.css" media="screen">':
                list_lines[index] = '<link rel="stylesheet"'\
                    ' href="' + path_html + 'VdBench.css" media="screen">'
            if val.strip() == '<script class="u-script" type="text/javascript" '\
                'src="nicepage.js" defer=""></script>':
                list_lines[index] = '<script class="u-script" type="text/javascript" '\
                    'src="href="' + path_html + 'nicepage.js" defer=""></script>'
            if val.strip() == '<img class="u-image u-image-1" src="images/new.png" '\
                'data-image-width="539" data-image-height="136">':
                list_lines[index] = '<img class="u-image u-image-1" '\
                    'src="'+path_html + 'images/new.png" '\
                        'data-image-width="539" data-image-height="136">'
        with open(self.destiny, "w") as file:
            for item in list_lines:
                file.write("%s\n" % item)
        file.close()
        msg = self.build + ' Result created succesfully'
        LogCreat().logger_info.info(msg)
        # except Exception as error:
        #     LogCreat().logger_error.error(error)
    def update_lines(self, workload, virtualdisk):
        '''
        This method append all results in HTML page

        Parameters
        ----------
        workload : str
            Type of workload
        virtualdisk : str
            Type of virtual disk (ILDC/ILC/ILD/STANDARD)

        Returns
        -------
        number : int
            line nubere where need to update data
        '''
        number = 0
        if workload.lower().strip() == 'vsi':
            start = 7
            number = self.repeate_loop(number, virtualdisk, start)
        elif workload.lower().strip() == 'vdi':
            start = 47
            number = self.repeate_loop(number, virtualdisk, start)
        elif workload.lower().strip() == 'oracle':
            start = 87
            number = self.repeate_loop(number, virtualdisk, start)
        else:
            start = 127
            number = self.repeate_loop(number, virtualdisk, start)
        return number
    def repeate_loop(self, number, virtualdisk, start):
        '''
        This method append all results in HTML page
        Parameters
        ----------
        number : int
            store line no for HTML page
        virtualdisk : str
            Type of virtual disk (ILDC/ILC/ILD/STANDARD)
        start : int
            start point of colum which used for HTML page

        Returns
        -------
        number : int
            line nubere where need to update data

        '''
        if virtualdisk.lower().strip() == 'ildc':
            number = start+1
        elif virtualdisk.lower().strip() == 'ild':
            number = start+2
        elif virtualdisk.lower().strip() == 'ilc':
            number = start+3
        else:
            number = start
        return number
    