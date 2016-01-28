#!/usr/bin/env python
# -*- encoding:utf-8 -*-

import datetime
import os.path
import time
import threading
try:
    from queue import Queue
except:
    from Queue import Queue
import binascii
import logging
import argparse
import json
import socket
import struct
try:
    import socketserver
except:
    import SocketServer as socketserver

import socks
import netaddr
import dnslib
from dnslib import RR, QTYPE, DNSRecord, DNSHeader


__version__ = '0.1.4'


logger = logging.getLogger(__name__)


class Domain(object):
    """
    @:    current domain
    """
    def __init__(self, name):
        self.name = name
        self.records = {}

    def __repr__(self):
        return '<Domain: %s>' % self.name

    def __str__(self):
        return '%s' % self.name

    def __bool__(self):
        return bool(self.records)

    def create(self, data):
        for typ, records in data.items():
            if typ in ['SOA']:
                dn = self.get_subdomain()
                self.records[dn] += [getattr(dnslib, typ)(
                    mname=self.get_subdomain(records['mname']),
                    rname=self.get_subdomain(records['rname']),
                    times=(
                        records['serial'],
                        records['refresh'],
                        records['retry'],
                        records['expire'],
                        records['minimum'],
                    )
                )]
            elif typ in ['NS', 'MX']:
                dn = self.get_subdomain()
                self.records[dn] += [
                    getattr(dnslib, typ)(self.get_subdomain(v)) for v in records
                ]
            elif typ in ['A', 'AAAA', 'TXT']:
                for name, value in records.items():
                    dn = self.get_subdomain(name)
                    self.records[dn] += [getattr(dnslib, typ)(v) for v in value]
            elif typ in ['CNAME']:
                for name, value in records.items():
                    dn = self.get_subdomain(name)
                    self.records[dn] += [
                        getattr(dnslib, typ)(self.get_subdomain(v)) for v in value
                    ]
            elif typ in ['SRV']:
                for name, value in records.items():
                    dn = self.get_subdomain(name)
                    for v in value:
                        v = v.split(' ')
                        self.records[dn].append(getattr(dnslib, typ)(
                            priority=int(v[0]),
                            weight=int(v[1]),
                            port=int(v[2]),
                            target=self.get_subdomain(v[3])
                        ))
            else:
                logger.warn('DNS Record %s(%s) need to be handled...' % (typ, name))

    def get_subdomain(self, subname='@'):
        if subname == '@':
            dn = self.name
        else:
            dn = subname + '.' + self.name
        if dn not in self.records:
            self.records[dn] = []
        return dn

    def output_records(self, out):
        for name, rrs in self.records.items():
            out('%s => %s' % (name, ', '.join([
                '%s(%s)' % (
                    rdata.__class__.__name__,
                    rdata) for rdata in rrs
            ])))

    def search(self, qn, qt):
        """
        qn: query domain name, DNSLabel
        qt: query domain type, default 'A' and 'AAAA'
        """
        r = []
        if qn.matchSuffix(self.get_subdomain()):
            for name, rrs in self.records.items():
                if name == qn:
                    for rdata in rrs:
                        rqt = rdata.__class__.__name__
                        if qt in ['*', rqt]:
                            r.append({
                                'type': rqt,
                                'rdata': rdata,
                            })
                            logger.debug('Find: %s => %s(%s)' % (
                                name, rqt, rdata
                            ))
                        elif rqt in ['CNAME']:
                            r.append({
                                'type': rqt,
                                'rdata': rdata,
                            })
                            logger.debug('Find: %s => %s(%s)' % (
                                name, rqt, rdata
                            ))
                            r += self.search(rdata.label, qt)
        return r


class BaseRequestHandler(socketserver.BaseRequestHandler):

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        logger.info('%s REQUEST %s' % ('=' * 35, '=' * 36))
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        client_ip = self.client_address[0]
        client_port = self.client_address[1]
        logger.warn("%s request %s (%s %s):" % (
            self.__class__.__name__[:3],
            now,
            client_ip, client_port,
        ))
        if client_ip not in allowed_hosts:
            logger.warn('\t*** Not allowed host: %s ***' % client_ip)
            return
        try:
            data = self.get_data()
            logger.info('%s %s' % (len(data), binascii.b2a_hex(data)))
            dns_response(self, data)
        except Exception as err:
            logger.fatal('send data: %s' % (err))


class TCPRequestHandler(BaseRequestHandler):

    def get_data(self):
        data = self.request.recv(8192).strip()
        sz = int(binascii.b2a_hex(data[:2]), 16)
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = bytes(binascii.a2b_hex(hex(len(data))[2:].zfill(4)))
        return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandler):

    def get_data(self):
        return self.request[0].strip()

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)


def lookup_local(handler, request):
    qn = request.q.qname
    qt = QTYPE[request.q.qtype]

    reply = DNSRecord(
        DNSHeader(id=request.header.id, qr=1, aa=1, ra=1),
        q=request.q
    )

    for domain in local_domains:
        rr_data = domain.search(qn, qt)
        for r in rr_data:
            answer = RR(
                rname=qn,
                rtype=getattr(QTYPE, r['type']),
                rclass=1, ttl=60 * 5,
                rdata=r['rdata'],
            )
            reply.add_answer(answer)

    if reply.rr:
        lines = []
        for r in reply.rr:
            rqn = r.rdata
            rqt = QTYPE[r.rtype]
            lines.append('\t\t%s(%s)' % (rqn, rqt))
        logger.warn('\tFrom LOCAL return:\n%s' % '\n'.join(lines))
        logger.info(reply)
        handler.send_data(reply.pack())
        return True
    return False


def do_lookup_upstream(data, dest, port=53,
                       tcp=False, timeout=None, ipv6=False,
                       proxy=None):
    """
        Send packet to nameserver and return response through proxy
        proxy_type: SOCKS5, SOCKS4, HTTP

        Note:: many proxy server only support TCP mode.
    """
    def get_sock(inet, stype, proxy=None):
        if proxy and proxy['enable']:
            sock = socks.socksocket(inet, stype)
            sock.set_proxy(
                socks.PROXY_TYPES[proxy['type']],
                proxy['ip'],
                proxy['port'],
            )
            logger.warn('\tProxy %(type)s://%(ip)s:%(port)s' % proxy)
        else:
            sock = socket.socket(inet, stype)
        return sock

    if ipv6:
        inet = socket.AF_INET6
    else:
        inet = socket.AF_INET
    if proxy and proxy['enable']:
        tcp = True
    if tcp:
        if len(data) > 65535:
            raise ValueError("Packet length too long: %d" % len(data))
        data = struct.pack("!H", len(data)) + data
        sock = get_sock(inet, socket.SOCK_STREAM, proxy)
        if timeout is not None:
            sock.settimeout(timeout)
        sock.connect((dest, port))
        sock.sendall(data)
        response = sock.recv(8192)
        length = struct.unpack("!H", bytes(response[:2]))[0]
        while len(response) - 2 < length:
            response += sock.recv(8192)
        sock.close()
        response = response[2:]
    else:
        sock = get_sock(inet, socket.SOCK_DGRAM, proxy)
        if timeout is not None:
            sock.settimeout(timeout)
        sock.sendto(data, (dest, port))
        response, server = sock.recvfrom(8192)
        sock.close()
    return response


def lookup_upstream_worker(queue, ip, port=53, timeout=None, proxy=None):
    while True:
        handler, request = queue.get()
        try:
            r_data = do_lookup_upstream(
                request.pack(),
                ip, port,
                timeout=timeout, proxy=proxy,
            )
            reply = DNSRecord.parse(r_data)
            if reply.rr:
                lines = []
                for r in reply.rr:
                    rqn = r.rdata
                    rqt = QTYPE[r.rtype]
                    lines.append('\t\t%s(%s)' % (rqn, rqt))
                logger.warn('\tFrom %s:%s return:\n%s' % (
                    ip, port,
                    '\n'.join(lines)
                ))
                logger.info(reply)
                handler.send_data(reply.pack())
        except Exception as err:
            logger.fatal('\tLookup from %s:%s: %s' % (ip, port, err))
        queue.task_done()


def dns_response(handler, data):
    request = DNSRecord.parse(data)

    qn = request.q.qname
    qt = QTYPE[request.q.qtype]
    logger.warn('\tRequest: %s(%s)' % (qn, qt))
    logger.info(request)

    found = False
    if config['server']['search'] in ['all', 'local']:
        found = lookup_local(handler, request)
    if not found and config['server']['search'] in ['all', 'upstream']:
        for t, q in upstreams:
            q.put((handler, request))


def init_config(config_file):
    log = {
        'file': 'homedns.log',
        'level': 30,
    }
    server = {
        'protocols': ['udp'],
        'listen_ip': '127.0.0.1',
        'listen_port': 53,
        # server: ip:port
        'upstreams': [
            '114.114.114.114',
            '114.114.115.115',
        ],
        'timeout': 10,
        # 'all', 'local' or 'upstream'
        'search': 'all',
        'allowed_hosts': ['127.0.0.1'],
    }
    proxy = {
        'enable': False,
        # type: SOCKS5, SOCKS4 and HTTP
        'type': 'SOCKS5',
        'ip': '127.0.0.1',
        'port': 1080,
    }
    domain = [{
        'name': 'mylocal.home',
        'enable': True,
        'records': {
            'NS': ['ns1', 'ns2'],
            'MX': ['mail'],
            'SOA': {
                'mname': 'ns1',
                'rname': 'mail',
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
            'A': {
                '@': ['127.0.0.1'],
                # MX and NS must be A record
                'ns1': ['127.0.0.1'],
                'ns2': ['127.0.0.1'],
                'mail': ['127.0.0.1'],
            },
            'AAAA': {
                '@': ['::1'],
                # MX and NS must be A record
                'ns1': ['::1'],
                'ns2': ['::1'],
                'mail': ['::1'],
            },
            'CNAME': {
                'www': ['@'],
                'ldap': ['www'],
                'kms': ['www'],
            },
            'TXT': {
                'fun': ['happy!'],
                'look': ['where?'],
                '@': ['my home', 'my domain']
            },
            'SRV': {
                '_ldap._tcp': ['0 100 389 ldap'],
                '_vlmcs._tcp': ['0 100 1688 kms'],
            },
        },
    }]
    global config
    global local_domains
    global allowed_hosts
    global upstreams
    if os.path.exists(config_file):
        config = json.load(open(config_file))
    else:
        config = {
            'log': log,
            'server': server,
            'proxy': proxy,
            'domain': domain,
        }
        json.dump(config, open(config_file, 'w'), indent=4)

    upstreams = []
    for up in config['server']['upstreams']:
        if ':' in up:
            ip, port = up.split(':')
            port = int(port)
        else:
            ip = up
            port = 53
        q = Queue()
        t = threading.Thread(
            target=lookup_upstream_worker,
            args=(q, ip, port),
            kwargs={
                'timeout': config['server']['timeout'],
                'proxy': config['proxy'],
            }
        )
        t.daemon = True
        t.start()
        upstreams.append((t, q))

    allowed_hosts = netaddr.IPSet()
    for hosts in config['server']['allowed_hosts']:
        if '*' in hosts or '-' in hosts:
            allowed_hosts.add(netaddr.IPGlob(hosts))
        elif '/' in hosts:
            allowed_hosts.add(netaddr.IPNetwork(hosts))
        else:
            allowed_hosts.add(hosts)

    local_domains = []
    for domain in config['domain']:
        if not domain['enable']:
            continue
        ld = Domain(domain['name'])
        ld.create(domain['records'])
        local_domains.append(ld)
    return config


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', action='version',
                        version='%%(prog)s %s' % __version__)
    parser.add_argument('-v', '--verbose', help='verbose help',
                        action='count', default=-1)
    parser.add_argument(
        '--config',
        help='read config from file',
        default='homedns.json',
    )
    args = parser.parse_args()

    init_config(args.config)

    __log_level__ = config['log']['level']
    if args.verbose >= 0:
        __log_level__ = logging.WARNING - (args.verbose * 10)

    if __log_level__ <= logging.DEBUG:
        formatter = '[%(name)s %(lineno)d] %(message)s'
    else:
        formatter = '%(message)s'

    if args.verbose >= 0:
        logging.basicConfig(
            format=formatter,
            level=__log_level__,
        )
    else:
        __log_file__ = config['log']['file']
        logging.basicConfig(
            filename=__log_file__,
            format=formatter,
            level=__log_level__,
        )

    logger.debug('Config: %s', config)
    logger.debug('Domain Record:')
    for domain in local_domains:
        logger.debug(domain)
        domain.output_records(logger.debug)

    logger.error("Starting nameserver...")

    ip = config['server']['listen_ip']
    port = config['server']['listen_port']

    logger.error('Listen on %s:%s' % (ip, port))

    servers = []
    if 'udp' in config['server']['protocols']:
        servers.append(
            socketserver.ThreadingUDPServer((ip, port), UDPRequestHandler)
        )
    if 'tcp' in config['server']['protocols']:
        servers.append(
            socketserver.ThreadingTCPServer((ip, port), TCPRequestHandler),
        )

    for s in servers:
        # that thread will start one more thread for each request
        thread = threading.Thread(target=s.serve_forever)
        # exit the server thread when the main thread terminates
        thread.daemon = True
        thread.start()
        logger.error("%s server loop running in thread: %s" % (
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
