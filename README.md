# python rawsocket tools
Fiddle with rawsocket in python3, implementing some commonly used network troubleshooting tools.
All the scripts need superuser privilege to run.
The traceroute and mtr scripts are not applicable to Windows, because I do not know and am not interested in how to modify IP header with python raw socket on Windows.

## ping
```
$ python3 pyping.py -h
usage: pyping.py [-h] [-d DATA | -s SIZE] [-i INTERVAL] [-w TIMEOUT]
                 [-c COUNT] [-t TTL] [-I INTERFACE] [-q] [-v]
                 target

ping in python3, need superuser privilege

positional arguments:
  target                address to ping

optional arguments:
  -h, --help            show this help message and exit
  -d DATA, --data DATA  set data used to ping
  -s SIZE, --size SIZE  set the size of data used to ping
  -i INTERVAL, --interval INTERVAL
                        set interval between each ping
  -w TIMEOUT, --timeout TIMEOUT
                        set socket timeout in second
  -c COUNT, --count COUNT
                        set the maximum count of ping; 0 means unlimited
  -t TTL, --ttl TTL     set time to live IP header field
  -I INTERFACE, --interface INTERFACE
                        set the interface to be bound
  -q, --quiet           suppress per ping echo message
  -v, --verbose         show verbose debug information
```

## traceroute
```
$ python3 pytraceroute.py -h
usage: pytraceroute.py [-h] [-s SIZE] [-i INTERVAL] [-w TIMEOUT] [-f FIRSTTL]
                       [-m MAXTTL] [-n NUMBER] [-p PORT] [-v] [-I | -U | -T]
                       target

traceroute in python3, need superuser privilege, supporting TCP, UDP and ICMP
probe

positional arguments:
  target                target address

optional arguments:
  -h, --help            show this help message and exit
  -s SIZE, --size SIZE  set the size of data used to traceroute
  -i INTERVAL, --interval INTERVAL
                        set interval between each packet sent
  -w TIMEOUT, --timeout TIMEOUT
                        set socket timeout in second
  -f FIRSTTL, --firsttl FIRSTTL
                        set the initial time to live IP header field
  -m MAXTTL, --maxttl MAXTTL
                        set the maximum time to live IP header field
  -n NUMBER, --number NUMBER
                        set the number of packets to be sent per hop
  -p PORT, --port PORT  set the destination port to test; only apply to TCP
                        and UDP traceroute; defalut to use various port;
  -v, --verbose         show verbose per hop RTT output
  -I, --icmp            use ICMP echo request to traceroute; the default
                        option, could be omitted
  -U, --udp             use UDP to traceroute
  -T, --tcp             use TCP syn to traceroute
```

## mtr
* pymtr.py: threading version;
* pymtr_asyn.py: asyncio version;
```
$ python3 pymtr.py -h
usage: pymtr.py [-h] [-s SIZE] [-i INTERVAL] [-w TIMEOUT] [-f FIRSTTL]
                [-m MAXTTL] [-n NUMBER] [-v] [-c CYCLE] [-r]
                target

mtr in python3 using threading, need superuser privilege, only ICMP
implemented; use ctrl+c to terminate

positional arguments:
  target                target address

optional arguments:
  -h, --help            show this help message and exit
  -s SIZE, --size SIZE  set the size of data used as probe
  -i INTERVAL, --interval INTERVAL
                        set interval between each packet sent
  -w TIMEOUT, --timeout TIMEOUT
                        set socket timeout in second
  -f FIRSTTL, --firsttl FIRSTTL
                        set the initial time to live IP header field
  -m MAXTTL, --maxttl MAXTTL
                        set the maximum time to live IP header field
  -n NUMBER, --number NUMBER
                        set the number of packets to be sent per hop
  -v, --verbose         show debug output
  -c CYCLE, --cycle CYCLE
                        set the count to cycle; defaluts to 0 meaning cycling
                        until terminated by user;
  -r, --report          report mode, supress output while running and display
                        the output when terminated instead; could be combined
                        with -c
```
```
$ python3 pymtr_asyn.py -h
usage: pymtr_asyn.py [-h] [-s SIZE] [-i INTERVAL] [-f FIRSTTL] [-m MAXTTL]
                     [-v] [-c CYCLE] [-r]
                     target

mtr in python3 using asynio, need superuser privilege, only ICMP implemented;
use ctrl+c to terminate;

positional arguments:
  target                target address

optional arguments:
  -h, --help            show this help message and exit
  -s SIZE, --size SIZE  set the size of data used as probe
  -i INTERVAL, --interval INTERVAL
                        set interval between each packet sent
  -f FIRSTTL, --firsttl FIRSTTL
                        set the initial time to live IP header field
  -m MAXTTL, --maxttl MAXTTL
                        set the maximum time to live IP header field
  -v, --verbose         show debug output
  -c CYCLE, --cycle CYCLE
                        set the count to cycle; defaluts to 0 meaning cycling
                        until terminated by user;
  -r, --report          report mode, supress output while running and display
                        the output when terminated instead; could be combined
                        with -c
```
