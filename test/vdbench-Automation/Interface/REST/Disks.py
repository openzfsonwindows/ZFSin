# -*- coding: utf-8 -*-
#pylint : disable=E0401
"""
@author: PRATEEK CHANDRA
DATACORE SOFTWARE PVT LTD CONFIDENTIAL
THIS SPEC IS THE PROPERTY OF DATACORE SOFTWARE PVT LTD.IT SHALL NOT BE
COPIED, USED,TRANSLATED OR TRANSFERRED IN WHOLE OR IN PART TO ANY THIRD
PARTY WITHOUT PRIOR WRITTEN PERMISSION OF DATACORE SOFTWARE PVT LTD.
File Name	:	Disks.py
Description	:	This script used to get physical disk details

"""
import os
import sys
path_ = os.path.abspath("../../../Interface")
sys.path.insert(0, path_)
from RestInterface import RestInterface
class Disks():
    '''
    This class used to get physical disk details
    Arguments : None
    Return: None
    '''
    physical_disk_data = ''
    def do_get_physical_disks(self, uri, header=None):
        '''
        This method used to get physical disk details
        Arguments (str, dict): uri, header
        Return (obj): physical_disk_data
        Parameters
        ----------
        uri : str
            url of REST API
        header : dict, optional
            Parameter to pass for request
        Returns
        -------
        self.physical_disk_data : obj
            request object which will say operation is passed or failed and consist
            informaton of operation.
        '''
        self.physical_disk_data = RestInterface().do_get_request(uri, req_header=header)
        return self.physical_disk_data
