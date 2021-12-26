# SendIOCs2ThreadFox

```diff
-=This script is written by me for learning Python. Try don't laugh at the code, PLS=-
```

```
$ ./send_iocs2ThreatFox.py -h
usage: send_iocs2ThreatFox.py [-h] [--threat Threat Type]
                              [--ioc_type IOC Type] -i IOC
                              [-t Tags [Tags ...]] [-m Malware Name]
                              [-c Comment] [-l Confidense] [-r Reference]

Send IOCs to ThrearFox by abuse.ch

optional arguments:
  -h, --help            show this help message and exit
  --threat Threat Type  Threat Type
  --ioc_type IOC Type   IOC Type
  -i IOC, --ioc IOC     IP:PORT to share (required)
  -t Tags [Tags ...], --tags Tags [Tags ...]
                        Tag, allowed characters: [A-Za-z0-9.-]
  -m Malware Name, --malware_name Malware Name
                        Name of malware: elf.bashlite (required)
  -c Comment, --comment Comment
                        Comments: use quotes `Your comments` (optional)
  -l Confidense, --confidense Confidense
                        Confidence level: (optional) Must be between 0-100.
                        Default: 50
  -r Reference, --reference Reference
                        Reference: use quotes `Your referenses` (optional)
```

![example](https://i.ibb.co/Yym34vj/carbon.png)
![ThreatFix_API](https://i.ibb.co/G5r5BmF/Screenshot-2021-12-21-Threat-Fox-API.png)
![IOCs](https://i.ibb.co/drdbkQF/Screenshot-2021-12-21-Threat-Fox-r3db-U7z.png)

Simple script for share (submit) an IOC to ThreatFox site https://threatfox.abuse.ch

I use this script to send IOCs, these are usually Gafgyt/Mirai botnets.

### WARNING
Use this only after editing and testing. If something explodes there, I'm not going to be responsible for it.

You can see more details about the ThreatFox API here: https://threatfox.abuse.ch/api/#threat-types

# Inspired by
This script partially uses the code from **urlhaus.py** by @cocaman -- https://github.com/cocaman/urlhaus
