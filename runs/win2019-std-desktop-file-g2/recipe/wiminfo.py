#!/usr/bin/python3
# wiminfo.py WIMXML -- one line per image from an install.wim's [1].xml
# (UTF-16): wim_index_N=EDITIONID | INSTALLATIONTYPE | MAJOR.MINOR.BUILD.SPBUILD | DISPLAYNAME
import sys
import xml.etree.ElementTree as ET
root = ET.fromstring(open(sys.argv[1], 'rb').read().decode('utf-16'))
for im in root.findall('IMAGE'):
    w = im.find('WINDOWS')
    v = w.find('VERSION')
    ver = '.'.join(v.findtext(k, '?') for k in ('MAJOR', 'MINOR', 'BUILD', 'SPBUILD'))
    print(f"wim_index_{im.get('INDEX')}={w.findtext('EDITIONID')} | {w.findtext('INSTALLATIONTYPE')} | {ver} | {im.findtext('DISPLAYNAME')}")
