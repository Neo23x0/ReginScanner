ReginScanner
============

Scanner for Regin Backdoor

Detection is based on four detection methods:

 1. File Name IOC 
    Based on the reports published by Symantec and Kaspersky

 2. Yara Ruleset
    Based on my rules published on pastebin:
    http://pastebin.com/0ZEWvjsC

 3. SHA256 hash check
    Compares known malicious SHA256 hashes with scanned files

 4. File System Scanner for Regin Virtual Filesystems
    based on .evt virtual filesystem detection by Paul Rascagneres, G DATA
    Reference: https://blog.gdatasoftware.com/blog/article/regin-an-old-but-sophisticated-cyber-espionage-toolkit-platform.html

The Windows binary is compiled with PyInstaller 2.1 and should run as x86 application on both x86 and x64 based systems.

Rule Base
============

The Yara rules published by Kaspersky are not bundled with this scanner. Extract them from the report and add them to the "regin_rules.yar" rule set to get better results. 
(Hint: Check the double quote signs " after copy&paste if errors occur)
https://securelist.com/files/2014/11/Kaspersky_Lab_whitepaper_Regin_platform_eng.pdf

Usage
============

usage: regin-scanner.py [-h] [-p path] [--dots] [--debug]

Regin Scanner

optional arguments:
  -h, --help  show this help message and exit
  -p path     Path to scan
  --dots      Print a dot for every scanned file to see the progress
  --debug     Debug output
  
Screenshots
============

ReginScanner reports system as clean

![ReginScannerScreen](/screens/ishot-141129-190200.png?raw=true "ReginScanner detecting file name IOC")

ReginScanner with detections

![ReginScannerScreen](/screens/ishot-141129-190453.png?raw=true "ReginScanner detecting Yara IOC")

Contact
============

Profile on Company Homepage
http://www.bsk-consulting.de/author/froth/

Twitter
@MalwrSignatures

If you are interested in a corporate solution for APT scanning, check:
http://www.bsk-consulting.de/apt-scanner-thor/
