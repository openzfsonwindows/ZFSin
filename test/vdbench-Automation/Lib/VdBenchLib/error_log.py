# -*- coding: utf-8 -*-
#pylint : disable=E0401
"""
@author: SUSHANT KEDAR
DATACORE SOFTWARE PVT LTD CONFIDENTIAL
THIS SPEC IS THE PROPERTY OF DATACORE SOFTWARE PVT LTD.IT SHALL NOT BE
COPIED, USED,TRANSLATED OR TRANSFERRED IN WHOLE OR IN PART TO ANY THIRD
PARTY WITHOUT PRIOR WRITTEN PERMISSION OF DATACORE SOFTWARE PVT LTD.
File Name	:	init_verification.py
Description	:	This script used to log the steps of vdbench

"""
import logging
from configparser import ConfigParser
class LogCreat():
    '''
    Class:- LogCreat
    This class is going to set levels for vdbench logging (INFO, ERROR)
    and will update details according to level
    Arguments : None
    Return: None
    '''
    def __init__(self):
        config_path = r'..\..\..\Config\VdBench_config\VDBench_config.ini'
        configur = ConfigParser()
        configur.read(config_path)
        time_stamp = configur.get('first run', 'start')
        self.file_path = r"../../../Test_Logs/VdBench_log_"+time_stamp+".log"
        self.logger_info = self.log_update()
        self.logger_error = self.error_update()
    def log_update(self):
        '''
        This method going to update INFO details of VdBench tool
        Returns
        -------
        logger : obj
            return logger object which help to append logs
        '''
        logging.basicConfig(filename=self.file_path, level=logging.INFO,
                            format='%(asctime)s %(levelname)s  %(message)s')

        logger = logging.getLogger(__name__)
        return logger

    def error_update(self):
        '''
        This method going to update ERROR details of VdBench tool
        Returns
        -------
        logger : obj
            return logger object which help to append logs
        '''
        logging.basicConfig(filename=self.file_path, level=logging.ERROR,
                            format='%(asctime)s %(levelname)s  %(message)s')
        logger = logging.getLogger(__name__)
        return logger
    