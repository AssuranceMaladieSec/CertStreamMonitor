#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is a part of CertStreamMonitor

import os
import sys
import datetime


class TimestampNow:
	'''Generate Timestamp'''
	def Timestamp(self):
		now = datetime.datetime.now().strftime("%c")
		return now

class VerifyPath:
	'''Verify or create file if not exist'''
	def VerifyOrCreate(self, file):
		try:
			os.makedirs(os.path.dirname(file), mode=0o777, exist_ok=True)
		except FileExistsError:
			pass 
		except:
			err = sys.exc_info()
			#print("[!!!] VerifyPath class Error: "+str(err))
			logging.error(" VerifyPath class Error: "+str(err))
