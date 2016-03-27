#!/usr/bin/env python
# -*- encoding:utf-8 -*-

import os.path
import argparse
import logging
import time
import json
import threading
from collections import OrderedDict

import netaddr

from . import py_version, globalvars
from .server import UDPRequestHandler, TCPRequestHandler, lookup_upstream_worker
from .domain import Domain, HostDomain
from .loader import TxtLoader, JsonLoader
from .adblock import Adblock
from .iniconfig import ini_read, ini_write
from .dhcp import getdns

if py_version == 3:
    import socketserver
    from queue import Queue
elif py_version == 2:
    import SocketServer as socketserver
    from Queue import Queue


def create_dns_service(server, proxy):
    q = Queue()
    t = threading.Thread(
        target=lookup_upstream_worker,
        args=(q, server),
        kwargs={
            'proxy': proxy if server['proxy'] else None
        }
    )
    t.daemon = True
    t.start()
    return {'queue': q, 'thread': t, 'count': 0, 'server': server}


def init_config(args):
    globalvars.init()

    globalvars.config_dir = os.path.abspath(os.path.dirname(args.config))
    globalvars.log_dir = globalvars.config_dir

    config_file = os.path.join(globalvars.config_dir, os.path.basename(args.config))
    fsplit = os.path.splitext(config_file)
    ini_file = fsplit[0] + '.ini'
    json_file = fsplit[0] + '.json'
    ext = fsplit[1].lower()
    if os.path.exists(config_file):
        if ext == '.ini':
            globalvars.config = ini_read(config_file)
        elif ext == '.json':
            globalvars.config = json.load(open(config_file))
        else:
            raise TypeError('Unknown config file: %s' % config_file)
    else:
        globalvars.config = {
            'log': globalvars.defaults.log,
            'server': globalvars.defaults.server,
            'smartdns': globalvars.defaults.smartdns,
            'domains': globalvars.defaults.domains,
        }
    if not os.path.exists(ini_file):
        ini_write(globalvars.config, ini_file)
    if not os.path.exists(json_file):
        json.dump(globalvars.config, open(json_file, 'w'), indent=4)

    if args.verbose >= 0:
        log_level = logging.WARNING - (args.verbose * 10)
    else:
        log_level = globalvars.config['log']['level']
    if log_level == logging.DEBUG:
        log_level2 = logging.DEBUG
    else:
        log_level2 = log_level - 10
    log_file = os.path.join(
        globalvars.log_dir,
        globalvars.config['log']['file']
    )
    formatter = logging.Formatter('%(message)s')
    if log_level2 == logging.DEBUG:
        formatter2 = logging.Formatter('[%(name)s %(lineno)d] %(message)s')
    else:
        formatter2 = formatter

    file_handler = logging.handlers.TimedRotatingFileHandler(
        filename=log_file,
        when='D',
        interval=1,
        backupCount=7,
        utc=False,
    )
    file_handler.setFormatter(formatter2)
    file_handler.setLevel(log_level2)
    file_handler.doRollover()

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(log_level)

    if '.' in __name__:
        app_logger = logging.getLogger(__name__.partition('.')[0])
    else:
        app_logger = logging.getLogger('homedns')
    app_logger.setLevel(logging.DEBUG)
    app_logger.addHandler(file_handler)
    app_logger.addHandler(console_handler)

    app_logger.warn('HomeDNS v%s' % globalvars.version)
    app_logger.warn('Config file: %s' % config_file)
    app_logger.warn('Log file: %s' % log_file)
    app_logger.debug('Config: %s', globalvars.config)

    global logger
    if '.' in __name__:
        logger = logging.getLogger(__name__)
    else:
        logger = logging.getLogger('homedns.' + __name__)

    proxy = globalvars.config['smartdns']['proxy']

    # bogus nxdomain
    globalvars.bogus_nxdomain = netaddr.IPSet()
    bogus = globalvars.config['smartdns']['bogus_nxdomain']
    name = 'bogus_nxdomain'
    loader = TxtLoader(
        bogus['url'],
        name=name,
        proxy=proxy if bogus['proxy'] else None,
    )
    if loader.local and not os.path.exists(loader.url):
        with open(loader.url, 'w') as f:
            f.write('# Generated by HomeDNS v%s\n' % globalvars.version)
            f.write('# Example:\n')
            f.write('#   192.168.1.0/24\n')
            f.write('#   192.168.2.10-100\n')
            f.write('#   192.168.3.*\n')
            f.write('#   192.168.*.*\n')
    try:
        loader_io = loader.open(cache=True)
    except Exception as err:
        logger.error('Load %s error: %s' % (name, err))
    for line in iter(loader_io.readline, ''):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if '*' in line or '-' in line:
            globalvars.bogus_nxdomain.add(netaddr.IPGlob(line))
        elif '/' in line:
            globalvars.bogus_nxdomain.add(netaddr.IPNetwork(line))
        else:
            globalvars.bogus_nxdomain.add(line)

    # upstream dns server
    upstreams = globalvars.upstreams = {}
    for name, value in globalvars.config['smartdns']['upstreams'].items():
        upstreams[name] = []
        dnssvr = list(value['ip'])
        while dnssvr:
            ip = dnssvr.pop()
            if ip.lower() == 'dhcp':
                dhcp_dnssvr = getdns()
                dnssvr += dhcp_dnssvr
                continue
            server = value.copy()
            server['ip'] = ip
            service = create_dns_service(server, proxy)
            upstreams[name].append(service)

    # rules
    globalvars.rules = OrderedDict()
    for rule in globalvars.config['smartdns']['rules']:
        name = rule['name']
        loader = TxtLoader(
            rule['url'],
            name=rule['name'],
            proxy=proxy if rule['proxy'] else None,
        )
        if loader.local and not os.path.exists(loader.url):
            if name == 'default' and rule['url'] == 'default.rules':
                with open(loader.url, 'w') as f:
                    f.write('! Generated by HomeDNS v%s\n' % globalvars.version)
                    f.write('! match all domains\n')
                    f.write('*.*\n')
            else:
                raise OSError('Not found Rule %s: %s' % (
                    name,
                    loader.url,
                ))
        logger.warn('Add rules "%s" - %s' % (name, loader))
        ab = Adblock(name)
        ab.create(loader)
        rule_dns = [upstreams[dns] for dns in rule['dns'] if dns in upstreams]
        logger.debug('Block list:\n\t' + '\n\t'.join(ab.output_list()))
        logger.info('DNS server:')
        for dns_domain in rule_dns:
            for dns_svr in dns_domain:
                logger.info('\t%s' % dns_svr['server']['ip'])
        globalvars.rules[name] = {
            'rule': ab,
            'upstreams': rule_dns,
            'refresh': rule['refresh'],
        }

    # allowed hosts
    globalvars.allowed_hosts = netaddr.IPSet()
    for hosts in globalvars.config['server']['allowed_hosts']:
        if '*' in hosts or '-' in hosts:
            globalvars.allowed_hosts.add(netaddr.IPGlob(hosts))
        elif '/' in hosts:
            globalvars.allowed_hosts.add(netaddr.IPNetwork(hosts))
        else:
            globalvars.allowed_hosts.add(hosts)

    # local domains
    globalvars.local_domains = {}
    for domain in globalvars.config['domains']:
        if domain['type'] == 'hosts':
            loader = TxtLoader(
                domain['url'],
                name=domain['name'],
                proxy=proxy if domain['proxy'] else None,
            )
            if loader.local and not os.path.exists(loader.url):
                if domain['name'] == 'hosts.homedns' and domain['url'] == 'hosts.homedns':
                    with open(loader.url, 'w') as f:
                        f.write('# Generated by HomeDNS v%s\n' % globalvars.version)
                        for host in globalvars.defaults.hosts_homedns:
                            f.write('%(ip)s\t%(name)s\n' % host)
                else:
                    raise OSError('Not found Domain %s: %s' % (
                        domain['name'],
                        loader.url,
                    ))
            logger.warn('Add domain %s - %s' % (domain['name'], loader))
            d = HostDomain(domain['name'])
            d.create(loader)
        elif domain['type'] == 'dns':
            loader = JsonLoader(
                domain['url'],
                name=domain['name'],
                proxy=proxy if domain['proxy'] else None,
            )
            if loader.local and not os.path.exists(loader.url):
                if domain['name'] == 'mylocal.home' and domain['url'] == 'mylocal.home.json':
                    json.dump(
                        globalvars.defaults.mylocal_home,
                        open(loader.url, 'w'),
                        indent=4,
                    )
                else:
                    raise OSError('Not found Domain %s: %s' % (
                        domain['name'],
                        loader.url,
                    ))
            logger.warn('Add domain %s - %s' % (domain['name'], loader))
            d = Domain(domain['name'])
            d.create(loader)
        logger.debug('Records:\n\t' + '\n\t'.join(d.output_records()))
        globalvars.local_domains[domain['name']] = {
            'domain': d,
            'refresh': domain['refresh'],
        }


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', action='version',
                        version='%%(prog)s %s' % globalvars.version)
    parser.add_argument('-v', '--verbose', help='verbose help',
                        action='count', default=0)
    parser.add_argument(
        '--config',
        help='read config from file',
        default='homedns.ini',
    )
    args = parser.parse_args()

    init_config(args)

    logger.warn("Starting nameserver...")

    ip = globalvars.config['server']['listen_ip']
    port = globalvars.config['server']['listen_port']

    logger.warn('Listen on %s:%s' % (ip, port))

    servers = []
    if 'udp' in globalvars.config['server']['protocols']:
        servers.append(
            socketserver.ThreadingUDPServer((ip, port), UDPRequestHandler)
        )
    if 'tcp' in globalvars.config['server']['protocols']:
        servers.append(
            socketserver.ThreadingTCPServer((ip, port), TCPRequestHandler),
        )

    for s in servers:
        # that thread will start one more thread for each request
        thread = threading.Thread(target=s.serve_forever)
        # exit the server thread when the main thread terminates
        thread.daemon = True
        thread.start()
        logger.warn("%s server loop running in thread: %s" % (
            s.RequestHandlerClass.__name__[:3],
            thread.name
        ))

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()

if __name__ == '__main__':
    run()
