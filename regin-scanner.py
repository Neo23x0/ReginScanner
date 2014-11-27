#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# Regin Scanner
#
# Detection is based on three detection methods:
#
# 1. File Name IOC 
#    Based on the reports published by Symantec and Kaspersky
#
# 2. Yara Ruleset
#    Based on my rules published on pastebin:
#    http://pastebin.com/0ZEWvjsC
#
# 3. File System Scanner for Regin Virtual Filesystems
#    based on .evt virtual filesystem detection by Paul Rascagneres, G DATA
#    Reference: https://blog.gdatasoftware.com/uploads/media/regin-detect.py
#
# If you like ReginScanner you'll love THOR our full-featured APT Scanner
# 
# Florian Roth
# BSK Consulting GmbH
# November 2014
# v0.3b
# 
# DISCLAIMER - USE AT YOUR OWN RISK.

import sys
import os
import argparse
import scandir
import traceback
import binascii
import yara

EVIL_FILES = [ '\\usbclass.sys', '\\adpu160.sys', '\\msrdc64.dat', '\\msdcsvc.dat', '\\config\\SystemAudit.Evt', '\\config\\SecurityAudit.Evt', '\\config\\SystemLog.evt', '\\config\\ApplicationLog.evt', '\\ime\\imesc5\\dicts\\pintlgbs.imd', '\\ime\\imesc5\\dicts\\pintlgbp.imd', 'ystem32\\winhttpc.dll', 'ystem32\\wshnetc.dll', '\\SysWow64\\wshnetc.dll', 'ystem32\\svcstat.exe', 'ystem32\\svcsstat.exe', 'IME\\IMESC5\\DICTS\\PINTLGBP.IMD', 'ystem32\\wsharp.dll', 'ystem32\\wshnetc.dll', 'pchealth\\helpctr\\Database\\cdata.dat', 'pchealth\\helpctr\\Database\\cdata.edb', 'Windows\\Panther\\setup.etl.000', 'ystem32\\wbem\\repository\\INDEX2.DATA', 'ystem32\\wbem\\repository\\OBJECTS2.DATA', 'ystem32\\dnscache.dat', 'ystem32\\mregnx.dat', 'ystem32\\displn32.dat', 'ystem32\\dmdskwk.dat', 'ystem32\\nvwrsnu.dat', 'ystem32\\tapiscfg.dat', 'ystem32\\pciclass.sys' ]

def scan(path):

	print "Scanning %s" % path
	
	# Compiling yara rules
	if os.path.exists('regin_rules.yar'):
		rules = yara.compile('regin_rules.yar')
	else: 
		print "Place the yara rule file 'regin_rules.yar' in the program folder to enable Yara scanning."

	for root, directories, files in scandir.walk(path, onerror=walkError, followlinks=False):
		for filename in files:
			filePath = os.path.join(root,filename)
			
			if args.dots:
				sys.stdout.write(".")
				
			if args.debug and not args.dots:
				print "Scanning: %s" % filePath
				
			file_size = os.stat(filePath).st_size
				
			# File Name Checks -------------------------------------------------
			for file in EVIL_FILES:
				if file in filePath:
					print "REGIN File Name MATCH: %s" % filePath
					
			# Yara Check -------------------------------------------------------
			if 'rules' in locals():
				if file_size < 500000:
					try:
						matches = rules.match(filePath)
						if matches:
							for match in matches:
								print "REGIN Yara Rule MATCH: %s FILE: %s" % ( match, filePath)
					except Exception, e:
						if args.debug:
							traceback.print_exc()
				
			# CRC Check --------------------------------------------------------
			try:
				if file_size <= 11:
					continue
				
				# Code from Paul Rascagneres
				fp = open(filePath, 'r')
				SectorSize=fp.read(2)[::-1]
				MaxSectorCount=fp.read(2)[::-1]
				MaxFileCount=fp.read(2)[::-1]
				FileTagLength=fp.read(1)[::-1]
				CRC32custom=fp.read(4)[::-1]
				fp.close()

				if args.debug:
					print "SectorSize: ", SectorSize.encode('hex')
					print "MaxSectorCount: ", MaxSectorCount.encode('hex')
					print "MaxFileCount: ", MaxFileCount.encode('hex')
					print "FileTagLength: ", FileTagLength.encode('hex')
					print "CRC32custom: ", CRC32custom.encode('hex')

				fp = open(filePath, 'r')
				data=fp.read(0x7)
				crc = binascii.crc32(data, 0x45)
				crc2 = '%08x' % (crc & 0xffffffff)
				if args.debug:
					print "CRC2: ", crc2.encode('hex')

				if CRC32custom.encode('hex') == crc2:
					print filePath,"REGIN Virtual Filesystem MATCH: %s" % filePath
			
			except Exception, e:
				if args.debug:
					traceback.print_exc()
			
def walkError(err):
    if args.debug:
        traceback.print_exc()			
				
def printWelcome():
	print "###############################################################################"
	print "  "
	print "  REGIN SCANNER"
	print "  "
	print "  by Florian Roth - BSK Consulting GmbH"
	print "  (virtual filesystem detection based code by Paul Rascagneres G DATA)"
	print "  Nov 2014"
	print "  Version 0.3b"
	print "  "
	print "  DISCLAIMER - USE AT YOUR OWN RISK"
	print "  "
	print "###############################################################################"                               

# MAIN ################################################################
if __name__ == '__main__':
	
	# Parse Arguments
	parser = argparse.ArgumentParser(description='Regin Scanner')
	parser.add_argument('-p', help='Path to scan', metavar='path', default='C:\\')
	parser.add_argument('--dots', action='store_true', help='Print a dot for every scanned file to see the progress', default=False)
	parser.add_argument('--debug', action='store_true', default=False, help='Debug output')
	
	args = parser.parse_args()
	
	# Print Welcome
	printWelcome()
	
	# Scan Path
	scan(args.p)