#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2018 Cnam 
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

VERSION = "0.3"

# Usage
def usage():
	usage = """
	-h --help		Print this help
	-c --config		Configuration file to use
	"""
	print (usage)
	sys.exit(0)

# Configuration
def ConfAnalysis(ConfFile):
	global CONF
	global DBFile
	global TABLEname
	global LogFile
	global SearchString

	try:
		CONF = ConfParser(ConfFile)

		DBFile = CONF.DBFile
		TABLEname = CONF.TABLEname
		LogFile = CONF.LogFile
		SearchString = CONF.SearchString

	except:
		err = sys.exc_info()
		logging.error(" ConfParser Error: "+str(err))

# Tool options
def args_parse():
	global ConfFile
	if not len(sys.argv[1:]):
		usage()
	try:
		opts, args = getopt.getopt(sys.argv[1:], "hc:", ["help", "conf="])
	except getopt.GetoptError as err:
		logging.error(" Option Error. Exiting..."+str(err))
		usage()
		sys.exit(2)

	for o,a in opts:
		if o in ("-h", "--help"):
			usage()
		elif o in ("-c", "--config"):
			if  os.path.isfile(a):
				ConfFile = a
			else:
				logging.error(" Can't find configuration file. Exiting...")
				sys.exit(1)
		else:
			assert False, "Unhandled Option"
	return

# CertStream
def print_callback(message, context):
	if message['message_type'] == "heartbeat":
		return

	if message['message_type'] == "certificate_update":
		all_domains = message['data']['leaf_cert']['all_domains']
		all_SAN = ",".join(message['data']['leaf_cert']['all_domains'][1:])

		if len(all_domains) == 0:
			domain = "NULL"
		else:
			domain = all_domains[0]

		if len(all_SAN) == 0:
			SAN = "NULL"
		else:
			SAN = all_SAN

	FindNb = len(re.findall(SearchString, (domain or SAN)))
	# If more than one search keyword occurence
	if FindNb > 1:
		# Data extraction to populate DB
		Domain = domain
		SAN = ",".join(message['data']['leaf_cert']['all_domains'][1:])
		Issuer =  message['data']['chain'][0]['subject']['aggregated']
		Fingerprint = message['data']['leaf_cert']['fingerprint']
		Startime = datetime.datetime.utcfromtimestamp(message['data']['leaf_cert']['not_before']).strftime('%d/%m/%y - %H:%M:%S UTC')
		FirstSeen = format(datetime.datetime.now().strftime('%d/%m/%y %H:%M:%S'))
		# Test if entry still exist in DB
		if SQL.SQLiteVerifyEntry(TABLEname, Domain) is 0:
			SQL.SQLiteInsert(TABLEname, Domain, SAN, Issuer, Fingerprint, Startime, FirstSeen)
			sys.stdout.write(u"[{}] {} (SAN: {}) (Issuer: {}) (Fingerprint: {}) (StartTime: {})\n".format(datetime.datetime.now().strftime('%d/%m/%y %H:%M:%S'), domain, ",".join(message['data']['leaf_cert']['all_domains'][1:]),message['data']['chain'][0]['subject']['aggregated'],message['data']['leaf_cert']['fingerprint'],datetime.datetime.utcfromtimestamp(message['data']['leaf_cert']['not_before']).strftime('%d/%m/%y - %H:%M:%S UTC')))
			sys.stdout.flush()


	# If just one keyword occurence, put data into debug log file
	elif FindNb == 1:
		logging.debug("{} (SAN: {}) (Issuer: {}) (Fingerprint: {}) (StartTime: {})".format(domain, ",".join(message['data']['leaf_cert']['all_domains'][1:]),message['data']['chain'][0]['subject']['aggregated'],message['data']['leaf_cert']['fingerprint'],datetime.datetime.utcfromtimestamp(message['data']['leaf_cert']['not_before']).strftime('%d/%m/%y - %H:%M:%S UTC')))

# Main
def main ():
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
