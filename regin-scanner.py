#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# Regin Scanner
# File System Scanner for Regin Virtual Filesystems
# based on .evt virtual filesystem detection by Paul Rascagneres, G DATA
# Reference: https://blog.gdatasoftware.com/uploads/media/regin-detect.py
#
# Florian Roth
# November 2014
# v0.1b
# 
# DISCLAIMER - USE AT YOUR OWN RISK.

import sys
import os
import argparse
import scandir
import traceback
import binascii

def scan(path):

	print "Scanning %s" % path

	for root, directories, files in scandir.walk(path, onerror=walkError, followlinks=False):
		for filename in files:
			filePath = os.path.join(root,filename)
			
			if args.dots:
				sys.stdout.write(".")
			
			try:
				if os.stat(filePath).st_size <= 11:
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
	print "  by Florian Roth"
	print "  BSK Consulting GmbH"
	print "  (based on .evt virtual filesystem detection by Paul Rascagneres G DATA)"
	print "  Nov 2014"
	print "  Version 0.1b"
	print "  "
	print "  DISCLAIMER - USE AT YOUR OWN RISK"
	print "  "
	print "###############################################################################"                               

# MAIN ################################################################
if __name__ == '__main__':
	
	# Parse Arguments
	parser = argparse.ArgumentParser(description='Regin Scanner')
	parser.add_argument('-p', help='Path to scan', metavar='path', default='C:\\')
	parser.add_argument('--dots', action='store_true', help='Print dot for every file to see the progress', default=False)
	parser.add_argument('--debug', action='store_true', default=False, help='Debug output')
	
	args = parser.parse_args()
	
	# Print Welcome
	printWelcome()
	
	# Scan Path
	scan(args.p)