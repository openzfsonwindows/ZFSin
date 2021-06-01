# -*- coding: utf-8 -*-
#pylint : disable=E0401
"""
@author: PRATEEK CHANDRA	
DATACORE SOFTWARE PVT LTD CONFIDENTIAL
THIS SPEC IS THE PROPERTY OF DATACORE SOFTWARE PVT LTD.IT SHALL NOT BE
COPIED, USED,TRANSLATED OR TRANSFERRED IN WHOLE OR IN PART TO ANY THIRD
PARTY WITHOUT PRIOR WRITTEN PERMISSION OF DATACORE SOFTWARE PVT LTD.
File Name	:	RestInterface.py
Description	:	This script used to access SSY Rest API

"""
import json
import requests
BASE_URL = 'http://localhost/RestService/rest.svc/1.0/'
from configparser import ConfigParser
class RestInterface:
    '''

    This class used to access SSY Rest API
    Arguments : None
    Return: None
    '''
    def __init__(self):
        configur = ConfigParser()
        configur.read(r"../../../Config/VdBench_config/VDBench_config.ini")
        USERNAME = "DcsAdmin"
        PASSWORD = configur.get('ssy login', 'pass_ssy').strip()
        self.headers = {'Content-Type': 'application/json', 'serverhost': 'localhost',
                        'Authorization': 'Basic ' + USERNAME + " " + PASSWORD}
    def do_post_request(self, req_uri, req_header=None, req_data=None):
        '''
        This class used to put post request
        Parameters
        ----------
        req_uri : str
            url used to hit REST API
        req_header : dict, optional
            Parameter to pass for request
        req_data : dict, optional
            Parameter to pass for request

        Returns
        -------
        req_res : obj
            request object which will say operation is passed or failed and consist
            informaton of operation.
        '''
        req_url = BASE_URL + req_uri
        if req_header is None:
            req_header = self.headers
        req_res = requests.request("POST", req_url, headers=req_header, data=json.dumps(req_data))
        return req_res
    def do_put_request(self, req_uri, req_header=None, req_data=None):
        '''
        This class used to put Put request
        Parameters
        ----------
        req_uri : str
            url used to hit REST API
        req_header : dict, optional
            Parameter to pass for request
        req_data : dict, optional
            Parameter to pass for request

        Returns
        -------
        req_res : obj
            request object which will say operation is passed or failed and consist
            informaton of operation.
        '''
        req_url = BASE_URL + req_uri
        if req_header is None:
            req_header = self.headers
        req_res = requests.request("PUT", req_url, headers=req_header, data=json.dumps(req_data))
        return req_res
    def do_get_request(self, req_uri, req_header=None):
        '''
        This class used to put Get request
        Parameters
        ----------
        req_uri : str
            url used to hit REST API
        req_header : dict, optional
            Parameter to pass for request

        Returns
        -------
        req_res : obj
            request object which will say operation is passed or failed and consist
            informaton of operation.
        '''
        req_url = BASE_URL + req_uri
        if req_header is None:
            req_header = self.headers
        req_res = requests.request("GET", req_url, headers=req_header)
        return req_res
    def do_delete_request(self, req_uri, req_header=None):
        '''
        This class used to put delete request
        Parameters
        ----------
        req_uri : str
            url used to hit REST API
        req_header : dict, optional
            Parameter to pass for request

        Returns
        -------
        req_res : obj
            request object which will say operation is passed or failed and consist
            informaton of operation.
        '''
        req_url = BASE_URL + req_uri
        if req_header is None:
            req_header = self.headers
        req_res = requests.request("DELETE", req_url, headers=req_header)
        return req_res
