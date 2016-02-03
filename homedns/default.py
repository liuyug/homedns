#!/usr/bin/env python
# -*- encoding:utf-8 -*-


log = {
    'file': 'homedns.log',
    'level': 30,
}
server = {
    # local listen on 'tcp', 'udp'
    'protocols': ['udp'],
    # local listen ip
    'listen_ip': '127.0.0.1',
    # local listen port
    'listen_port': 53,
    # search domain from 'all', 'local' or 'upstream'
    'search': 'all',
    # allowed hosts to access
    # 192.168.1.0/24, 192.168.2.10-100, 192.168.3.*
    'allowed_hosts': ['127.0.0.1'],
}
smartdns = {
    # If enable is Ture
    # forward DNS request through proxy by rules
    # or
    # forward all request to every server without proxy
    'enable': True,
    'rules': ['customs.rules'],
    'proxy': {
        # proxy type: SOCKS5, SOCKS4 or HTTP
        'type': 'SOCKS5',
        # proxy ip
        'ip': '127.0.0.1',
        # proxy port
        'port': 1080,
        # ignore if smartdns enable is True
        'enable': False,
    },
    # upstream dns server
    'upstreams': [
        {
            'ip': '114.114.114.114',
            'port': 53,
            'tcp': True,
            'timeout': 5,
            'type': 'white',
        },
        {
            'ip': '114.114.115.115',
            'port': 53,
            'tcp': True,
            'timeout': 5,
            'type': 'white',
        },
        {
            'ip': '8.8.8.8',
            'port': 53,
            'tcp': True,
            'timeout': 5,
            'type': 'black',
        },
        {
            'ip': '8.8.4.4',
            'port': 53,
            'tcp': True,
            'timeout': 5,
            'type': 'black',
        },
    ],
}
domain = [{
    # domain name
    'name': 'mylocal.home',
    # enable to search the domain
    'enable': True,
    # domain records
    'records': {
        # dns NS record
        'NS': ['ns1', 'ns2'],
        # dns MX record
        'MX': ['mail'],
        # dns SOA record
        'SOA': {
            # primary dns server
            'mname': 'ns1',
            # dns contact email address. '@' is replaced by '.'
            'rname': 'admin',
            'serial': 20160101,
            # 60 * 60 * 1
            'refresh': 3600,
            # 60 * 60 * 3
            'retry': 10800,
            # 60 * 60 * 24
            'expire': 86400,
            # 60 * 60 * 1
            'minimum': 3600,
        },
        # dns A record. ipv4
        'A': {
            # '@' is current domain
            '@': ['127.0.0.1'],
            # MX and NS domain name must be A record
            'ns1': ['127.0.0.1'],
            'ns2': ['127.0.0.1'],
            'mail': ['127.0.0.1'],
        },
        # dns A record. ipv6
        'AAAA': {
            '@': ['::1'],
            'ns1': ['::1'],
            'ns2': ['::1'],
            'mail': ['::1'],
        },
        # dns CNAME record. alias domain.
        'CNAME': {
            'www': ['@'],
            'ldap': ['www'],
            'kms': ['www'],
        },
        # dns TXT record
        'TXT': {
            'fun': ['happy!'],
            'look': ['where?'],
            '@': ['my home', 'my domain'],
        },
        # dns SRV record
        'SRV': {
            '_ldap._tcp': ['0 100 389 ldap'],
            '_vlmcs._tcp': ['0 100 1688 kms'],
        },
        'PTR': {
            '127.0.0': ['@'],
        },
    },
}]
