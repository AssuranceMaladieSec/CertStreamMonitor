#!/opt/venv/bin/python3
# -*- coding: utf-8 -*-

# Copyright (c) 2018-2021 Caisse nationale d'Assurance Maladie
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

import os
import re
import sys
import getopt
import logging
import datetime
import certstream
from logging.handlers import RotatingFileHandler
from utils.confparser import ConfParser
from utils.utils import TimestampNow, VerifyPath
from utils.sqlite import SqliteCmd

VERSION = "0.7.2"

def usage():
    """
    CLI usage printing
    """
    usage = """
    -h --help       Print this help
    -c --config     Configuration file to use
    """
    print(usage)
    sys.exit(0)


def ConfAnalysis(ConfFile):
    """
    configuration file analysis. Load global variables with parameters found
    in configuration file.

    :param  ConfFile: the configuration file
    """
    global CONF
    global DBFile
    global TABLEname
    global LogFile
    global LogLevel
    global LogType
    global SearchKeywords
    global BlacklistKeywords
    global DetectionThreshold
    global ACTServer
    global Proxy_Host
    global Proxy_Port
    global Proxy_Username
    global Proxy_Password

    try:
        CONF = ConfParser(ConfFile)

        DBFile = CONF.DBFile
        TABLEname = CONF.TABLEname
        LogFile = CONF.LogFile
        LogLevel = CONF.LogLevel
        #LogLevel needs to be converted to int
        LogLevel = int(LogLevel)  
        LogType = CONF.LogType
        SearchKeywords = CONF.SearchKeywords
        BlacklistKeywords = CONF.BlacklistKeywords
        DetectionThreshold = CONF.DetectionThreshold
        ACTServer = CONF.ACTServer
        Proxy_Host = CONF.Proxy_Host
        Proxy_Port = CONF.Proxy_Port
        Proxy_Username = CONF.Proxy_Username
        Proxy_Password = CONF.Proxy_Password

    except:
        err = sys.exc_info()
        logging.error(" ConfParser Error: " + str(err))


def args_parse():
    """
    Tool options
    """
    global ConfFile
    if not len(sys.argv[1:]):
        usage()
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hc:", ["help", "conf="])
    except getopt.GetoptError as err:
        logging.error(" Option Error. Exiting..." + str(err))
        usage()
        sys.exit(2)

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-c", "--config"):
            if os.path.isfile(a):
                ConfFile = a
            else:
                logging.error(" Can't find configuration file. Exiting...")
                sys.exit(1)
        else:
            assert False, "Unhandled Option"
    return

# CertStream


def print_callback(message, context):
    """
    callback that is going to be called at each CertStream message reception
    """
    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']

    # look for pattern on *each* hostname
    for host in all_domains:
        is_blacklisted = False
        if BlacklistKeywords != str():
            is_blacklisted = re.findall(BlacklistKeywords, host)
        results = re.findall(SearchKeywords, host)
        FindNb = len(set(results))

        # Matching host whith blacklisted keywords are ignored
        if is_blacklisted and FindNb >= DetectionThreshold:
            continue

        # If search keywords occurence in the hostname is greater or equal to DetectionThreshold
        # we store the hostname into DB
        if FindNb >= DetectionThreshold:
            # Data extraction to populate DB
            Domain = host
            SAN = ""
            Issuer = message['data']['leaf_cert']['subject']['aggregated']
            Fingerprint = message['data']['leaf_cert']['fingerprint']
            Startime = datetime.datetime.utcfromtimestamp(
                message['data']['leaf_cert']['not_before']).isoformat()
            FirstSeen = format(datetime.datetime.utcnow(
            ).replace(microsecond=0).isoformat())
            # Test if entry still exist in DB
            if SQL.SQLiteVerifyEntry(TABLEname, Domain) == 0:
                SQL.SQLiteInsert(TABLEname, Domain, SAN, Issuer, Fingerprint, Startime, FirstSeen)
                sys.stdout.write(u"[{}] {} (SAN: {}) (Issuer: {}) (Fingerprint: {}) (StartTime: {})\n".format(datetime.datetime.now().replace(microsecond=0).isoformat(), host, "", message['data']['leaf_cert']['issuer']['aggregated'], message['data']['leaf_cert']['fingerprint'], datetime.datetime.utcfromtimestamp(message['data']['leaf_cert']['not_before']).isoformat()))
                sys.stdout.flush()

        # If just one keyword occurence, put data into debug log file
        elif FindNb > 0 and FindNb < DetectionThreshold:
            logging.debug("DETECTION THRESHOLD VALUE NOT REACHED - {} (SAN: {}) (Issuer: {}) (Fingerprint: {}) (StartTime: {})".format(host, "", message['data']['leaf_cert']['issuer']['aggregated'], message['data']['leaf_cert']['fingerprint'], datetime.datetime.utcfromtimestamp(message['data']['leaf_cert']['not_before']).isoformat()))


# Main
def main():
    global SQL
    try:
        # Config
        ConfAnalysis(ConfFile)
        P = VerifyPath()
        # Create files
        P.VerifyOrCreate(DBFile)
        P.VerifyOrCreate(LogFile)
        # Database
        SQL = SqliteCmd(DBFile)
        SQL.SQLiteCreateTable(TABLEname)

        # logging
        logger = logging.getLogger()
        logger.setLevel(LogLevel)

        # file handler (10MB, 10 rotations)
        if LogType == 'file':
            format = logging.Formatter(
                '[%(levelname)s:%(name)s] %(asctime)s - %(message)s')
            file_handler = RotatingFileHandler(LogFile, 'a', 10000000, 10)
            file_handler.setFormatter(format)
            logger.addHandler(file_handler)
        # syslog handler
        elif LogType == 'syslog':
            stream_handler = logging.StreamHandler()
            logger.addHandler(stream_handler)
        else:
            logging.error("Unsupported log type " + LogType + ". Exiting...")
            sys.exit(1)

        # Work, connection to the CT logs aggregator (ACTServer), through a HTTP proxy if configured into configuration file
        logging.info("Looking for these strings: " + SearchKeywords +
                     ", detection threshold: " + str(DetectionThreshold))
        certstream.listen_for_events(print_callback, ACTServer, http_proxy_host=Proxy_Host,
                                     http_proxy_port=Proxy_Port, http_proxy_auth=(Proxy_Username, Proxy_Password))
        print_callback()

        SQL.SQLiteClose()

    except:
        err = sys.exc_info()
        logging.error(" Main error " + str(err))


# Start
if __name__ == '__main__':
    args_parse()
    main()
