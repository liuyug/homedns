=========
HOMEDNS
=========
This is a tiny DNS server only for family used.

Support python2 and python3.

.. note::

    Use TCP connection when proxy enable

Feature
=======
1. Local FAKE domain. DNS Record: A, AAAA, CNAME, NS, MX, TXT, SRV...
#. Forward DNS request to upstream DNS server with TCP or UDP mode.
#. Proxy support. Connect to upstream server through PROXY server
#. Support Adblock RUlE. Filter the request by rule and forward it to upstream DNS server.
#. Local "hosts" file, resolve domain name by hosts content.
#. Support non-standard DNS port, default 53
#. Support DNS-over-HTTPS with google protocol

hosts rules
============
Default hosts filename is 'hosts'. The format is the same as system hosts.

example:

    127.0.0.1   localhost


TODO
====

Pack
------
::

    pyinstaller --icon App-browser.ico --clean --noupx --noconfirm --console --paths homedns --onefile hdns.py

Sample
=======
server::

    # python homedns.py -v
    Starting nameserver...
    Listen on 127.0.0.1:53
    UDP server loop running in thread: Thread-1

    UDP request 2016-01-28 02:48:41.508710 (127.0.0.1 59115):
            Request: 1.0.0.127.in-addr.arpa.(PTR)
    UDP request 2016-01-28 02:48:43.510825 (127.0.0.1 59118):
            Request: www.mylocal.home.mylocal.home.(A)
    UDP request 2016-01-28 02:48:45.511939 (127.0.0.1 59121):
            Request: www.mylocal.home.mylocal.home.(AAAA)
    UDP request 2016-01-28 02:48:47.514054 (127.0.0.1 59124):
            Request: www.mylocal.home.(A)
            From LOCAL return:
                    mylocal.home.(CNAME)
                    127.0.0.1(A)
    UDP request 2016-01-28 02:48:47.517054 (127.0.0.1 59125):
            Request: www.mylocal.home.(AAAA)
            From LOCAL return:
                    mylocal.home.(CNAME)
                    ::1(AAAA)
    UDP request 2016-01-28 02:50:50.061063 (127.0.0.1 59126):
            Request: 1.0.0.127.in-addr.arpa.(PTR)
    UDP request 2016-01-28 02:50:52.064177 (127.0.0.1 59129):
            Request: mylocal.home.mylocal.home.(TXT)
    UDP request 2016-01-28 02:50:54.065292 (127.0.0.1 59132):
            Request: mylocal.home.(TXT)
            From LOCAL return:
                    "my home"(TXT)
                    "my domain"(TXT)

client::

    C:\nslookup www.mylocal.home 127.0.0.1
    Server:  UnKnown
    Address:  127.0.0.1

    Name:    www.mylocal.home
    Addresses:  ::1
              127.0.0.1
    Aliases:  www.mylocal.home

    C:\nslookup -type=txt mylocal.home 127.0.0.1
    mylocal.home    text =

            "my home"
    mylocal.home    text =

            "my domain"
