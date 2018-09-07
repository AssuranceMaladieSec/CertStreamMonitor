#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2018 Caisse nationale d'Assurance Maladie
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

VERSION = "0.4.1"


def usage():
    """
    CLI usage printing
    """
    usage = """
    -h --help       Print this help
    -c --config     Configuration file to use
    """
    print (usage)
    sys.exit(0)


def ConfAnalysis(ConfFile):
    """
    configuration file analysis. Load global variables with parameters found
    in configuration file.

    :param  confFile: the configuration file
    """
    global CONF
    global DBFile
    global TABLEname
    global LogFile
    global SearchString
    global DetectionThreshold

    try:
        CONF = ConfParser(ConfFile)

        DBFile = CONF.DBFile
        TABLEname = CONF.TABLEname
        LogFile = CONF.LogFile
        SearchString = CONF.SearchString
        DetectionThreshold = CONF.DetectionThreshold

    except:
        err = sys.exc_info()
        logging.error(" ConfParser Error: "+str(err))


def args_parse():
    """
    Tools options
    """
    global ConfFile
    if not len(sys.argv[1:]):
        usage()
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hc:", ["help", "conf="])
    except getopt.GetoptError as err:
        logging.error(" Option Error. Exiting..."+str(err))
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

        if len(all_domains) == 0:
            all_domains_str = "NULL"
        else:
            # convert domains list to a string of domains separate by space in order to be able to look for hostnames
            all_domains_str = ' '.join(all_domains)

    # build of the regexp pattern for the findall function : string + patterns + string
    pattern = r"[\w\.-]*(?:" + SearchString + ")[\w\.-]*"

    results = re.findall(pattern, all_domains_str)
    FindNb = len(set(results))

    # If more than one search keyword occurence
    if FindNb >= DetectionThreshold:
        # Data extraction to populate DB
        for domainfound in results:
            Domain = domainfound
            SAN = ""
            Issuer = message['data']['chain'][0]['subject']['aggregated']
            Fingerprint = message['data']['leaf_cert']['fingerprint']
            Startime = datetime.datetime.utcfromtimestamp(
                message['data']['leaf_cert']['not_before']).isoformat()
            FirstSeen = format(datetime.datetime.utcnow().replace(microsecond=0).isoformat())
            # Test if entry still exist in DB
            if SQL.SQLiteVerifyEntry(TABLEname, Domain) is 0:
                SQL.SQLiteInsert(TABLEname, Domain, SAN, Issuer, Fingerprint, Startime, FirstSeen)
                sys.stdout.write(u"[{}] {} (SAN: {}) (Issuer: {}) (Fingerprint: {}) (StartTime: {})\n".format(datetime.datetime.now().replace(microsecond=0).isoformat(), Domain, "", message['data']
                                                                                                              ['chain'][0]['subject']['aggregated'], message['data']['leaf_cert']['fingerprint'], datetime.datetime.utcfromtimestamp(message['data']['leaf_cert']['not_before']).isoformat()))
                sys.stdout.flush()

    # If just one keyword occurence, put data into debug log file
    elif FindNb > 0 and FindNb < DetectionThreshold:
        logging.debug("DETECTION THRESHOLD VALUE NOT REACHED - {} (SAN: {}) (Issuer: {}) (Fingerprint: {}) (StartTime: {})".format(results, "",
                                                                                                                                   message['data']['chain'][0]['subject']['aggregated'], message['data']['leaf_cert']['fingerprint'], datetime.datetime.utcfromtimestamp(message['data']['leaf_cert']['not_before']).isoformat()))

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
        logger.setLevel(logging.DEBUG)

        # file handler (10MB, 10 rotations)
        format = logging.Formatter('[%(levelname)s:%(name)s] %(asctime)s - %(message)s')
        file_handler = RotatingFileHandler(LogFile, 'a', 10000000, 10)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(format)
        logger.addHandler(file_handler)

        # term handler
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(logging.INFO)
        logger.addHandler(stream_handler)

        # Work
        logging.info("Looking for these strings: "+SearchString)
        certstream.listen_for_events(print_callback)
        print_callback()

        SQL.SQLiteClose()

    except:
        err = sys.exc_info()
        logging.error(" Main error " + str(err))


# Start
if __name__ == '__main__':
    args_parse()
    main()
