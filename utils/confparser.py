#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is a part of CertStreamMonitor

import os
import sys
import logging
import configparser


class ConfParser:
    '''Configuration file parser'''

    def __init__(self, Confile=None):
        try:
            self.config = configparser.ConfigParser()

            with open(Confile, 'r', encoding='utf-8') as f:
                self.config.readfp(f)

                # search strings
                self.SearchKeywords = self.config['SEARCH']['SearchKeywords']
                try:
                    self.BlacklistKeywords = self.config['SEARCH']['BlacklistKeywords']
                except KeyError:
                    self.BlacklistKeywords = str()

                # Databases
                self.DBFile = self.config['DATABASE']['DBFile']
                self.TABLEname = self.config['DATABASE']['TABLEname']

                # Logging
                self.LogFile = self.config['LOGGING']['LogFile']

                # Proxy
                try:
                    self.Proxy = self.config['CONNECT']['Proxy']
                except:
                    self.Proxy = None

                # Reporting
                self.Alerts_dir = self.config['REPORTING']['Alerts_dir']
                try:
                    self.Notification_Destination = self.config['REPORTING']['Notification_Destination']
                except:
                    self.Notification_Destination = None

                # User Agent
                self.http_UA = self.config['CONNECT']['http_UA']

                # User Agent list file
                self.UAfile = self.config['CONNECT']['UAfile']

                # Detection Threshold
                try:
                    self.DetectionThreshold = int(
                        self.config['SEARCH']['DetectionThreshold'])
                except:
                    self.DetectionThreshold = 1

                # CT logs aggregator server connection
                try:
                    self.ACTServer = self.config['SERVER']['ACTServer']
                except:
                    logging.error(
                        " Configuration file Error: You need a CT logs Aggregator server to connect on...")
                    sys.exit(1)

                try:
                    self.Proxy_Host = self.config['SERVER']['Proxy_Host']
                except:
                    self.Proxy_Host = None

                try:
                    self.Proxy_Port = self.config['SERVER']['Proxy_Port']
                except:
                    self.Proxy_Port = None

                try:
                    self.Proxy_Username = self.config[
                        'SERVER']['Proxy_Username']
                except:
                    self.Proxy_Username = None

                try:
                    self.Proxy_Password = self.config[
                        'SERVER']['Proxy_Password']
                except:
                    self.Proxy_Password = None

                # Safe Browsing Status check
                try:
                    self.Safe_Browsing_API_Key = self.config['SAFEBROWSING']['Safe_Browsing_API_Key']
                except:
                    self.Safe_Browsing_API_Key = ''

        except IOError:
            #print("[!!!] Configuration file Error: "+Confile)
            logging.error(" Configuration file Error: " + Confile)

        except:
            err = sys.exc_info()
            #print("[!!!] ConfParser Error: "+str(err))
            logging.error(" ConfParser Error: " + str(err))
