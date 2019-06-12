#!/usr/bin/env python3
"""
GetHost display the last findings
"""

# Copyright (c) 2018-2019 Caisse nationale d'Assurance Maladie
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# Standard library imports
from __future__ import absolute_import
from datetime import datetime
import getopt
import os
import sys

# Third party library imports
from sqlite3 import connect, Error

# Own library imports
from utils.confparser import ConfParser

# Debug
from pdb import set_trace as st

def create_connection(db_file):
    """ create a database connection to the SQLite database
        specified by the db_file

    :param db_file: database file
    :return: Connection object or None
    """

    try:
        conn = connect(db_file, isolation_level=None)
        # debug SQL
        # conn.set_trace_callback(print)
        return conn
    except Error as err:
        print(err)
        return False


def args_parse():
    """
    Tools options
    """
    global CONFFILE
    global SINCE
    SINCE = 3600 # One hour

    if not len(sys.argv[1:]):
        usage()
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hc:", ["help", "conf=", "since="])
    except getopt.GetoptError as err:
        print(" Option Error. Exiting..."+str(err))
        usage()
        sys.exit(2)

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-c", "--config"):
            if os.path.isfile(a):
                CONFFILE = a
            else:
                print(" Can't find configuration file. Exiting...")
                sys.exit(1)
        elif o in ("--since"):
            SINCE = int(a)
        else:
            assert False, "Unhandled Option"
    return


def usage():
    """
    CLI usage printing
    """
    usage = """
    -h --help		Print this help
    -c --config		Configuration file to use
    --since      Since when it displays findings (seconds)
     """
    print(usage)
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

    try:
        CONF = ConfParser(ConfFile)
        DBFile = CONF.DBFile
        TABLEname = CONF.TABLEname
    except Exception as err:
        err = sys.exc_info()
        print("ConfParser Error: "+str(err))


def parse_and_display_all_hostnames(TABLEname, conn, print_output=False):
    """
    Parse and display all hostnames present in DB ""

    :param TABLEname: the table name storing certificate informations in database
    :param conn: db connection

    :return: True if everything went fine, False if something went wrong    
    """
    try:
        # Query rows that have not StillInvestig column already set
        # get Domain and Fingerprint column
        cur = conn.cursor()
        cur.execute("SELECT Domain,FirstSeen,StillInvestig FROM "+TABLEname)
        rows = cur.fetchall()
        result = dict()

        # run scan on each hostname
        for row in rows:
            domain = row[0]
            first_seen = row[1]
            still_investing = row[2]
            first_seen_date = datetime.strptime(first_seen, '%Y-%m-%dT%H:%M:%S')
            since = (datetime.utcnow() - first_seen_date).total_seconds()
            if since < SINCE:
                result.update({domain: {"still_investing": still_investing}})
                if print_output:
                    print("{} {}".format(domain, still_investing))
        return result

    except KeyboardInterrupt:
        if print_output:
            print("Interrupt received, stopping ...")
            print("start - committing, closing DB")
        conn.commit
        conn.close
        if print_output:
            print("ending - committing, closing DB")
        return result

    except Exception as err:
        if print_output:
            print(err)
        return result


def main():
    ConfAnalysis(CONFFILE)

    # create a database connection
    conn = create_connection(DBFile)

    with conn:
        print("Display all domains in DB for Internet Presence:")
        print("************************************************")
        parse_and_display_all_hostnames(TABLEname, conn, print_output=True)


if __name__ == '__main__':
    args_parse()
    main()
