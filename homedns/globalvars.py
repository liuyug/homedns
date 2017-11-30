#!/usr/bin/env python
# -*- encoding:utf-8 -*-

version = '0.1.35'


class defaults():
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
        # search domain from 'local' or 'upstream'
        'search': ['local', 'upstream'],
        # allowed hosts to access
        # 192.168.1.0/24, 192.168.2.10-100, 192.168.3.*, 192.168.*.*
        'allowed_hosts': ['127.0.0.1'],
    }
    smartdns = {
        # match rule by order in list.
        'rules': [
            {
                'name': 'black',
                'url': 'https://github.com/liuyug/homedns/raw/master/black.rules',
                'proxy': False,
                'refresh': 60 * 60 * 8,
                'dns': ['gdns'],
            },
            {
                'name': 'default',
                'url': 'default.rules',
                'proxy': False,
                'refresh': 60 * 60 * 8,
                'dns': ['114dns'],
            },
        ],
        'hack_srv': ['_ldap._tcp'],
        'bogus_nxdomain': {
            'url': 'bogus-nxdomain.lst',
            'proxy': False,
            'refresh': 60 * 60 * 8,
            'hack_ip': '',
        },
        'proxy': {
            # proxy type: SOCKS5, SOCKS4 or HTTP
            'type': 'SOCKS5',
            # proxy ip
            'ip': '127.0.0.1',
            # proxy port
            'port': 1080,
        },
        # upstream dns server
        'upstreams': {
            '114dns': {
                'ip': ['114.114.114.114', '114.114.115.115'],
                'port': 53,
                'timeout': 2,
                'proxy': False,
                'tcp': False,
                'priority': 50,
            },
            'gdns': {
                'ip': ['8.8.8.8', '8.8.4.4'],
                'port': 53,
                'timeout': 2,
                'proxy': True,
                'tcp': True,
                'priority': 50,
            },
        },
    }
    domains = [
        {
            'name': 'mylocal.home',
            'url': 'mylocal.home.json',
            'proxy': False,
            'type': 'dns',
            'refresh': 60 * 60 * 8,
        },
        {
            'name': 'hosts.homedns',
            'url': 'hosts.homedns',
            'proxy': False,
            'type': 'hosts',
            'refresh': 60 * 60 * 8,
        },
    ]
    hosts_homedns = [
        {'name': 'unknown.cisco.com', 'ip': '127.0.0.1'},
        {'name': 'unknown.yahoo.com', 'ip': '127.0.0.1'},
    ]
    mylocal_home = {
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
            'refresh': 60 * 60 * 1,
            'retry': 60 * 60 * 3,
            'expire': 60 * 60 * 24,
            'minimum': 60 * 60 * 1,
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
            'www': ['@'],  # internal alias
            'ldap': ['www'],
            'kms': ['www'],
            'vps': ['@vps.ddns.net'],  # extern alias
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
            '127.0.0.2': ['@'],
            '::2': ['@'],
        },
    }


def init():
    global config
    global local_domains
    global allowed_hosts
    global upstreams
    global rules
    global bogus_nxdomain
    global config_dir
    global log_dir
    global dig  # dig format output
