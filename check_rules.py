#!/usr/bin/env python3

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
from utils.confparser import ConfParser
from utils.utils import VerifyPath

VERSION = "0.0.1"

def usage():
    """
    CLI usage printing
    """
    usage_output = """
    -h --help       Print this help
    -c --config     Configuration file to use
    -d --domain     Domain name to check
    """
    print(usage_output)
    sys.exit(0)


def ConfAnalysis(configuration_file):
    """
    configuration file analysis. Load global variables with parameters found
    in configuration file.

    :param  configuration_file: the configuration file
    """
    global CONF
    global SearchKeywords
    global BlacklistKeywords
    global DetectionThreshold

    try:
        CONF = ConfParser(configuration_file)

        SearchKeywords = CONF.SearchKeywords
        BlacklistKeywords = CONF.BlacklistKeywords
        DetectionThreshold = CONF.DetectionThreshold
    except:
        err = sys.exc_info()
        logging.error(" ConfParser Error: %s", err)


def args_parse():
    """
    Tool options
    """
    global ConfFile
    global DOMAIN
    if not len(sys.argv[1:]):
        usage()
    try:
        opts, _ = getopt.getopt(sys.argv[1:], "hc:d:", ["help", "conf="])
    except getopt.GetoptError as err:
        logging.error(" Option Error. Exiting... %s", err)
        usage()
        sys.exit(2)

    DOMAIN = None
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-c", "--config"):
            if os.path.isfile(a):
                ConfFile = a
            else:
                logging.error(" Can't find configuration file. Exiting...")
                sys.exit(1)
        elif o in ("-d", "--domain"):
            DOMAIN = a
        else:
            assert False, "Unhandled Option"
    if not DOMAIN:
        usage()
        sys.exit(2)


def print_callback():
    """
    Truncate CertStreamMonitor/print_callback function, SQL/Logging support removed
    """
    is_blacklisted = False
    if BlacklistKeywords != str():
        is_blacklisted = re.findall(BlacklistKeywords, DOMAIN)
    results = re.findall(SearchKeywords, DOMAIN)
    FindNb = len(set(results))

    # Matching host whith blacklisted keywords are ignored
    if is_blacklisted and FindNb >= DetectionThreshold:
        logging.info("No match - Blacklisted keywords.")
        return

    # If search keywords occurence in the hostname is greater or equal to DetectionThreshold
    if FindNb >= DetectionThreshold:
        logging.info("This is a match, detection threashold reached.")
    elif FindNb > 0 and FindNb < DetectionThreshold:
        logging.info("No match - Detection threashold not reached.")
    else:
        logging.info("No match - Keywords not found.")
    return


# Main
def main():
    # Config
    ConfAnalysis(ConfFile)
    VerifyPath()

    # logging
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # term handler
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)
    logger.addHandler(stream_handler)
    logging.info(
        "Looking for these strings: %s, detection threshold: %s",
        SearchKeywords,
        DetectionThreshold)
    print_callback()


# Start
if __name__ == '__main__':
    args_parse()
    main()
