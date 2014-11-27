ReginScanner
============

Scanner for Regin Backdoor

Detection is based on three detection methods:

 1. File Name IOC 
    Based on the reports published by Symantec and Kaspersky

 2. Yara Ruleset
    Based on my rules published on pastebin:
    http://pastebin.com/0ZEWvjsC

 3. File System Scanner for Regin Virtual Filesystems
    based on .evt virtual filesystem detection by Paul Rascagneres, G DATA
    Reference: https://blog.gdatasoftware.com/blog/article/regin-an-old-but-sophisticated-cyber-espionage-toolkit-platform.html

The Windows binary is compiled with PyInstaller 2.1 and should run as x86 application on both x86 and x64 based systems.

Usage
============

usage: regin-scanner.py [-h] [-p path] [--dots] [--debug]

Regin Scanner

optional arguments:
  -h, --help  show this help message and exit
  -p path     Path to scan
  --dots      Print a dot for every scanned file to see the progress
  --debug     Debug output

