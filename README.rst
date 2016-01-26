=========
HOMEDNS
=========
This is a tiny DNS server only for family used.

Support python2 and python3.

Feature
=======
1. DNS Record: A, AAAA, CNAME, NS, MX, TXT, SRV...
#. proxy dns. To transfer to upstream dns server
#. TCP and UDP connection

TODO
====

Pack
------
::

    pyinstaller --clean --noupx -c -F homedns.py

