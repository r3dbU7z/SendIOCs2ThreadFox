#!/usr/bin/env python

import string
import requests
import urllib3
import json
import argparse
import re

from pygments import highlight, lexers, formatters

__author__ = "@r3dbU7z"
__copyright__ = "Copyright 2021, @r3dbU7z "
__license__ = "Creative Commons Attribution-ShareAlike 4.0 International License."
__version__ = "0.0.8"

# Prepare HTTPSConnectionPool
headers = {
  "API-KEY":        "YOUR-API-KEY-HERE", # <-- EDIT THIS
}
pool = urllib3.HTTPSConnectionPool('threatfox-api.abuse.ch', port=443, maxsize=50, headers=headers, cert_reqs='CERT_NONE', assert_hostname=True)

# threat_type      - Query https://threatfox.abuse.ch/api/#types to get the appropriate
#                    threat_type / ioc_type combination
# ioc_type         - Query https://threatfox.abuse.ch/api/#types to get the appropriate
#                    threat_type / ioc_type combination
# malwareinfo      - Query https://threatfox.abuse.ch/api/#malware-list to get the appropriate
#                  - malware family or search through Malpedia web UI: https://malpedia.caad.fkie.fraunhofer.de/
# confidence_level - Optional; Must be between 0-100. Default: 50
# reference        - Optional; Must be a URL if provided
# Comment          - Optional; Your comment on the IOC(s) you want to submit
# anonymous        - Optional; 0 (false) or 1 (true). Default: 0 (false)
# tag_list         - Optional; List of tags
# iocs             - list of IOCs you want to submit

# helper function to check that a tag has the right format [A-Za-z0-9.-]
def check_tag_regex(s):
    if s == "":
        return 
    p = re.compile(r'([a-zA-Z\.-]+)')
    m = p.match(s)
    if m == None or not m.group() == s:
        raise argparse.ArgumentTypeError("Invalid tag used '" + s + "'")
    return str(s)

parser = argparse.ArgumentParser(description='Upload a malware sample to Malware Bazaar by abuse.ch')
parser.add_argument(
	'--threat',
	dest='threat_type',
	help='Threat Type',
	type=str, metavar="Threat Type",
	default="botnet_cc"
)
parser.add_argument(
	'--ioc_type',
	dest='ioc_type',
	help='IOC Type',
	type=str,
	metavar="IOC Type",
	default="ip:port"
)
parser.add_argument(
	'-i', '--ioc',
	dest='ioc',
	help='IP:PORT to share (required)',
	type=str, metavar="IOC",
	required=True
)
#Without Default arguments
#parser.add_argument('-t', '--tags', dest='tags', help='Tag, allowed characters: [A-Za-z0-9.-]', required=False, type=check_tag_regex, metavar="Tags", nargs="+")
parser.add_argument(
	'-t', '--tags',
	dest='tags',
	help='Tag, allowed characters: [A-Za-z0-9.-]',
	required=False,
	type=check_tag_regex,
	metavar="Tags",
	default=["Gafgyt"],
	nargs="+"
)
#Without Default arguments
#parser.add_argument('-m', '--malware_name', dest='malware', help='Name of malware: elf.bashlite (required)', type=str, metavar="Malware Name", required=True)
parser.add_argument(
	'-m',
	'--malware_name',
	dest='malware',
	help='Name of malware: elf.bashlite (required)',
	type=str,
	metavar="Malware Name",
	default="elf.bashlite"
)
parser.add_argument(
	'-c',
	'--comment',
	dest='comment',
	help='Comments: use quotes `Your comments` (optional)',
	type=str,
	metavar="Comment",
	default=''
)
parser.add_argument(
	'-l',
	'--confidense',
	dest='confidence',
	help='Confidence level: (optional) Must be between 0-100. Default: 50',
	type=str,
	metavar="Confidense",
	default="50"
)
parser.add_argument(
	'-r', '--reference',
	dest='reference',
	help='Reference: use quotes `Your referenses` (optional)',
	type=str,
	metavar="Reference",
	default=''
)

args = parser.parse_args()
threat_type = args.threat_type
ioc_type  = args.ioc_type
malware = args.malware
comment = args.comment
tag = args.tags
confidence_level = args.confidence
reference = args.reference
ioc = args.ioc

print("\nThreat Type: " + threat_type)
print("IOC Type: " + ioc_type)
print("Malware Name: " + malware)
print("Tag(s): " + ''.join(args.tags))
print("\n")

data = {
    'query':            'submit_ioc',
    'threat_type':      threat_type,
    'ioc_type':         ioc_type,
    'malware':          malware,
    'confidence_level': confidence_level,
    'reference':        reference,
    'comment':          comment,
    'anonymous':        0,
    'tags':    tag,
    'iocs': [
        ioc
    ]
}

json_data = json.dumps(data, indent=4, sort_keys=True)
response = pool.request("POST", "/api/v1/", body=json_data)
response = response.data.decode("utf-8", "ignore")
#print(json_data)
#print(response)
colorful_json = highlight(response, lexers.JsonLexer(), formatters.TerminalTrueColorFormatter())
print(colorful_json)
