=========
HOMEDNS
=========
This is a tiny DNS server only for family used.

Support python2 and python3.

Feature
=======
1. DNS Record: A, AAAA, CNAME, NS, MX, TXT, SRV...
#. proxy dns. To forward request to upstream dns server
#. TCP and UDP connection
#. config file based json format

TODO
====

Pack
------
::

    pyinstaller --clean --noupx -c -F homedns.py

Sample
=======
server::

    # python homedns.py -v
    Starting nameserver...
    Listen on 127.0.0.1:53
    UDP server loop running in thread: Thread-1
    UDP request 2016-01-26 03:26:42.141264 (127.0.0.1 54479):
            Request: 1.0.0.127.in-addr.arpa.(PTR)
            Lookup from LOCAL
            Lookup from 114.114.114.114:53(1)
            Lookup from 114.114.115.115:53(1)
            Return : N/A
    UDP request 2016-01-26 03:26:42.343276 (127.0.0.1 54482):
            Request: mylocal.home.mylocal.net.(TXT)
            Lookup from LOCAL
            Lookup from 114.114.114.114:53(2)
            Lookup from 114.114.115.115:53(2)
            Return : N/A
    UDP request 2016-01-26 03:26:42.469283 (127.0.0.1 54485):
            Request: mylocal.home.ibm.com.(TXT)
            Lookup from LOCAL
            Lookup from 114.114.114.114:53(3)
            Lookup from 114.114.115.115:53(3)
            Return : N/A
    UDP request 2016-01-26 03:26:42.717297 (127.0.0.1 54488):
            Request: mylocal.home.(TXT)
            Lookup from LOCAL
            Return : "my home"(TXT)
            Return : "my domain"(TXT)

client::

    C:\nslookup -type=txt mylocal.home 127.0.0.1
    Server:  UnKnown
    Address:  127.0.0.1

    mylocal.home    text =

            "my home"
    mylocal.home    text =

            "my domain"
