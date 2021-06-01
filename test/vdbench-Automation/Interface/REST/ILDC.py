# -*- coding: utf-8 -*-
#pylint : disable=E0401
"""
@author: PRATEEK CHANDRA
DATACORE SOFTWARE PVT LTD CONFIDENTIAL
THIS SPEC IS THE PROPERTY OF DATACORE SOFTWARE PVT LTD.IT SHALL NOT BE
COPIED, USED,TRANSLATED OR TRANSFERRED IN WHOLE OR IN PART TO ANY THIRD
PARTY WITHOUT PRIOR WRITTEN PERMISSION OF DATACORE SOFTWARE PVT LTD.
File Name	:	ILDC.py
Description	:	This script used to access REST API of SSY.
"""
import sys
import os
import subprocess
path_ = os.path.abspath("../../../Interface")
sys.path.insert(0, path_)
from RestInterface import RestInterface
class ILDC():
    '''
    This class used to access REST API of SSY.
    Arguments : None
    Return: None
    '''
    def __init__(self):
        self.result = ''
        self.process = ''
    def do_enable_capacity_optimization(self, uri, header=None, payload=None):
        '''
        This method used to post request of enable capacity optimization at server level
        Parameters
        ----------
        uri : str
            url of REST API
        header : dict, optional
            Parameter to pass for request
        payload : dict, optional
            operational parameters which i need to perform

        Returns
        -------
        self.result : obj
            request object which will say operation is passed or failed
        '''
        self.result = RestInterface().do_post_request(uri, req_header=header, req_data=payload)
        return self.result
    def do_create_pool(self, uri, header=None, payload=None):
        '''
        This method used to post request of create diskpool
        Parameters
        ----------
        uri : str
            url of REST API
        header : dict, optional
            Parameter to pass for request
        payload : dict, optional
            operational parameters which i need to perform

        Returns
        -------
        self.result : obj
            request object which will say operation is passed or failed
        '''
        self.result = RestInterface().do_post_request(uri,
                                                      req_header=header, req_data=payload)
        return self.result
    def do_create_vd(self, uri, header=None, payload=None):
        '''
        This method used to post request of create VD
        Parameters
        ----------
        uri : str
            url of REST API
        header : dict, optional
            Parameter to pass for request
        payload : dict, optional
            operational parameters which i need to perform

        Returns
        -------
        self.result : obj
            request object which will say operation is passed or failed
        '''
        self.result = RestInterface().do_post_request(uri, req_header=header, req_data=payload)
        return self.result
    def do_serve_vd(self, uri, header=None, payload=None):
        '''
        This method used to post request of serve VD to host
        Parameters
        ----------
        uri : str
            url of REST API
        header : dict, optional
            Parameter to pass for request
        payload : dict, optional
            operational parameters which i need to perform

        Returns
        -------
        self.result : obj
            request object which will say operation is passed or failed
        '''
        self.result = RestInterface().do_post_request(uri, req_header=header, req_data=payload)
        return self.result
    def do_serve_on_off(self, uri, header=None, payload=None):
        '''
        This method used to post request of ON/OFF SSY server
        Arguments (str, dict, dict): uri, header, payload
        Return (obj): self.reqest
        '''
        self.result = RestInterface().do_post_request(uri,
                                                      req_header=header, req_data=payload)
        return self.result
    def do_disable_capacity_optimization(self, uri, header=None, payload=None):
        '''
        This method used to post request of disable capacity optimization at server level
        Parameters
        ----------
        uri : str
            url of REST API
        header : dict, optional
            Parameter to pass for request
        payload : dict, optional
            operational parameters which i need to perform

        Returns
        -------
        self.result : obj
            request object which will say operation is passed or failed
        '''
        self.result = RestInterface().do_post_request(uri, req_header=header, req_data=payload)
        return self.result
    def do_enable_cap_opt_on_vd(self, uri, header=None, payload=None):
        '''
        This method used to put request to the SSY to set VD properties.
        Parameters
        ----------
        uri : str
            url of REST API
        header : dict, optional
            Parameter to pass for request
        payload : dict, optional
            operational parameters which i need to perform

        Returns
        -------
        self.result : obj
            request object which will say operation is passed or failed
        '''
        self.result = RestInterface().do_put_request(uri, req_header=header, req_data=payload)
        return self.result
    def do_ssy_details(self, uri, header=None):
        '''
        This method used to get SSY details like SSY status
        Parameters
        ----------
        uri : str
            url of REST API
        header : dict, optional
            Parameter to pass for request
        Returns
        -------
        self.result : obj
            request object which will say operation is passed or failed
        '''
        self.result = RestInterface().do_get_request(uri, req_header=header)
        return self.result
    def do_pool_delete(self, uri):
        '''
        This method used to delete request to delete diskpool
        ex: delete Vd
        Parameters
        ----------
        uri : str
            url of REST API
        Returns
        -------
        self.result : obj
            request object which will say operation is passed or failed
        '''
        self.result = RestInterface().do_delete_request(uri)
        return self.result
    def do_vd_delete(self, uri):
        '''
        This method used to delete request to delete VD
        Parameters
        ----------
        uri : str
            url of REST API
        Returns
        -------
        self.result : obj
            request object which will say operation is passed or failed
        '''
        self.result = RestInterface().do_delete_request(uri)
        return self.result
    def clean_diskpart(self, list_disk):
        '''
        This method used to clean disk using diskpart
        Parameters
        ----------
        list_disk : int
            disk index which help to clean disk

        Returns
        -------
        None.
        '''
        self.process = subprocess.Popen(['diskpart'], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        encoding='utf8', universal_newlines=True, bufsize=0,
                                        creationflags=subprocess.CREATE_NEW_CONSOLE, shell=False)
        self.process.stdin.write("select disk "+str(list_disk) + "\n")
        self.process.stdin.write("clean"+ "\n")
        self.process.stdin.write("exit"+ "\n")
        self.process.stdin.close()
    def initial_disk(self, disk):
        '''
        This method used to initialize Virtual disk.
        Parameters
        ----------
        disk : int
            disk index which help to clean disk and initalize it.

        Returns
        -------
        None.
        '''
        self.process = subprocess.Popen(['diskpart'], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        encoding='utf8', universal_newlines=True, bufsize=0,
                                        creationflags=subprocess.CREATE_NEW_CONSOLE, shell=False)
        self.process.stdin.write("select disk "+str(disk) + "\n")
        self.process.stdin.write("ATTRIBUTES DISK CLEAR READONLY"+ "\n")
        self.process.stdin.write("online disk noerr"+"\n")
        self.process.stdin.write("clean"+"\n")
        self.process.stdin.write("create part pri"+ "\n")
        self.process.stdin.write("select part 1"+"\n")
        self.process.stdin.write("format fs=raw quick "+"\n")
        self.process.stdin.write("assign=None"+"\n")
        self.process.stdin.close()
        