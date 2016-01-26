=========
HOMEDNS
=========
This is a tiny DNS server only for family used.

Feature
=======
1. DNS Record: A, AAAA, CNAME, NS, MX, TXT, SRV...
#. proxy dns. To transfer to upstream dns server
#. TCP and UDP connection

TODO
====
1. support many dns upstream server.

Pack
------
::

    pyinstaller --clean --noupx -w -F homedns.py

