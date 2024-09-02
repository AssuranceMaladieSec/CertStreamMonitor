#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is a part of CertStreamMonitor

import sqlite3
import sys

class SqliteCmd(object):
	'''Sqlite3 DB commands'''
	def __init__(self, DBfile):
		self.conn = sqlite3.connect(DBfile)
		self.cur = self.conn.cursor()

		## Main DB operations
	def SQLiteCreateTable(self, TABLEname):
		'''Creating main Table if not exist'''
		self.cur.execute('CREATE TABLE IF NOT EXISTS '+TABLEname+' (Domain TEXT NOT NULL PRIMARY KEY, SAN TEXT, Issuer TEXT, Fingerprint TEXT, Startime TEXT, FirstSeen TEXT, StillInvestig TEXT)')

	def SQLiteInsert(self, TABLEname, Domain, SAN, Issuer, Fingerprint, Startime, FirstSeen):
		'''Insert new entry infos'''
		self.cur.execute('INSERT OR IGNORE INTO '+TABLEname+' (Domain, SAN, Issuer, Fingerprint, Startime, FirstSeen) VALUES (?,?,?,?,?,?);', (Domain, SAN, Issuer, Fingerprint, Startime, FirstSeen))
		self.conn.commit()

	def SQLiteVerifyEntry(self, TABLEname, Domain):
		'''Verify if entry still exist'''
		res = self.cur.execute('SELECT EXISTS (SELECT 1 FROM '+TABLEname+' WHERE Domain='+"\""+Domain+"\""+' LIMIT 1);')
		fres = res.fetchone()[0]
		# 0ô
		if fres != 0:
			return 1
		else:
			return 0

	def __del__(self):
	    try:
	        self.cur.close()
	        self.conn.close()
	    except:
	        pass
	    
	def SQLiteClose(self):
		self.__del__()
