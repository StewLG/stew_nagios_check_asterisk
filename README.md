# stew_nagios_check_asterisk
Nagios plug-in to check Asterisk using AMI interface.

SIP Peer check:
```
$ ./StewCheckAsterisk.py -H ani.doodle.local -u nagios_ami -p password_goes_here -ct sippeer
OK - Peer your_voip_provider Status OK (7 ms) - 177.111.22.3 SIP
```

SIP Registration check, all peers:
```
$ ./StewCheckAsterisk.py -H ani.doodle.local -u nagios_ami -p password_goes_here -ct sipregistry
OK - Registered Host: toronto.yourvoipprovider.com State: Registered
```

