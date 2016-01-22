#!/usr/bin/env python
# -*- encoding:utf-8 -*-

import datetime
import os.path
import sys
import time
import threading
import traceback
import SocketServer
import logging
import argparse
import json

import dnslib
from dnslib import RR, QTYPE, DNSLabel, DNSRecord, DNSHeader


__version__ = '0.1.0'


logger = logging.getLogger(__name__)
local_domain = {}


class DomainName(str):
    def __getattr__(self, item):
        if item == '@':
            return self
        else:
            return DomainName(item + '.' + self)


class BaseRequestHandler(SocketServer.BaseRequestHandler):

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        logger.info('%s REQUEST %s' % ('=' * 35, '=' * 36))
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        logger.info("%s request %s (%s %s):" % (
            self.__class__.__name__[:3],
            now,
            self.client_address[0],
            self.client_address[1]
        ))
        try:
            data = self.get_data()
            logger.debug('%s %s' % (len(data), data.encode('hex')))
            self.send_data(dns_response(data))
        except Exception:
            traceback.print_exc(file=sys.stderr)


class TCPRequestHandler(BaseRequestHandler):

    def get_data(self):
        data = self.request.recv(8192).strip()
        sz = int(data[:2].encode('hex'), 16)
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = hex(len(data))[2:].zfill(4).decode('hex')
        return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandler):

    def get_data(self):
        return self.request[0].strip()

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)


def lookup_local_domain(qn, qt):
    r = []
    if qn.matchSuffix(local_domain['name']):
        for name, rrs in local_domain['record'].iteritems():
            if name == qn:
                for rdata in rrs:
                    rqt = rdata.__class__.__name__
                    if qt in ['*', rqt]:
                        r.append({
                            'type': rqt,
                            'rdata': rdata,
                        })
                        logger.debug('%s => %s(%s)' % (name, rdata, rqt))
                    if rqt in ['CNAME']:
                        r.append({
                            'type': rqt,
                            'rdata': rdata,
                        })
                        logger.debug('%s => %s(%s)' % (name, rdata, rqt))
                        r += lookup_local_domain(rdata.label, qt)
    return r


def lookup_local(request, reply):
    qn = request.q.qname
    qt = QTYPE[request.q.qtype]

    rr_data = lookup_local_domain(qn, qt)
    for r in rr_data:
        answer = RR(
            rname=qn,
            rtype=getattr(QTYPE, r['type']),
            rclass=1, ttl=60 * 5,
            rdata=r['rdata'],
        )
        if qt == r['type']:
            reply.add_answer(answer)
        else:
            reply.add_answer(answer)

    return reply


def lookup_upstream(request, reply):
    logger.info('%s REPLY %s' % ('-' * 36, '-' * 37))
    logger.info(reply)
    for up in config['server']['upstreams']:
        try:
            if ':' in up:
                ip, port = up.split(':')
                port = int(port)
            else:
                ip = up
                port = 53
            r_data = request.send(ip, port, timeout=config['server']['timeout'])
        except Exception as err:
            logging.warn('Lookup upstream: %s' % err)
            continue
        r_reply = DNSRecord.parse(r_data)
        for rr in r_reply.rr:
            reply.add_answer(rr)
    return reply


def dns_response(data):
    request = DNSRecord.parse(data)
    logger.info(request)

    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

    reply = lookup_local(request, reply)
    if not reply.rr:
        reply = lookup_upstream(request, reply)

    logger.info('%s REPLY %s' % ('-' * 36, '-' * 37))
    logger.info(reply)

    return reply.pack()


def init_config(config_file):
    log = {
        'file': 'homedns.log',
        'level': 0,
    }
    server = {
        'protocols': ['udp'],
        'listen_ip': '127.0.0.1',
        'listen_port': 53,
        'upstreams': ['114.114.114.114'],
        'timeout': 10,
    }
    domain = {
        'name': 'mylocal.net',
        '@': {
            'NS': ['ns1', 'ns2',],
            'MX': ['mail',],
            'A': '127.0.0.1',
            'AAAA': '::1',
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
        },
        'A': {
            # MX and NS must be A record
            'ns1': ['127.0.0.1'],
            'ns2': ['127.0.0.1'],
            'mail': ['127.0.0.1'],
        },
        'AAAA': {
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
            'fun': 'happy!',
            'look': 'where?',
        },
        'SRV': {
            '_ldap._tcp': ['0 100 389 ldap'],
            '_vlmcs._tcp': ['0 100 1688 kms'],
        },
    }
    if os.path.exists(config_file):
        config = json.load(open(config_file), encoding='ascii')
    else:
        config = {
            'log': log,
            'server': server,
            'domain': domain,
        }
        json.dump(config, open(config_file, 'w'), indent=4)
    DOMAIN = DomainName(config['domain'].get('name', ''))
    if not DOMAIN:
        return config
    domain_record = {}
    local_domain['name'] = DNSLabel(DOMAIN)
    local_domain['record'] = domain_record
    domain_record[DOMAIN] = []
    for typ, records in config['domain'].items():
        if typ == 'name':
            pass
        elif typ == '@':
            for typ, value in records.items():
                if typ in ['NS', 'MX']:
                    domain_record[DOMAIN] += [getattr(dnslib, typ)(getattr(DOMAIN, v)) for v in value]
                elif typ in ['A', 'AAAA']:
                    domain_record[DOMAIN] += [getattr(dnslib, typ)(value)]
                elif typ in ['SOA']:
                    domain_record[DOMAIN] += [getattr(dnslib, typ)(
                        mname=getattr(DOMAIN, value['mname']),
                        rname=getattr(DOMAIN, value['rname']),
                        times=(
                            value['serial'],
                            value['refresh'],
                            value['retry'],
                            value['expire'],
                            value['minimum'],
                        )
                    )]
        elif typ in ['A', 'AAAA']:
            for name, value in records.items():
                dn = getattr(DOMAIN, name)
                if dn not in domain_record:
                    domain_record[dn] = []
                domain_record[dn] += [getattr(dnslib, typ)(v) for v in value]
        elif typ in ['CNAME']:
            for name, value in records.items():
                dn = getattr(DOMAIN, name)
                if dn not in domain_record:
                    domain_record[dn] = []
                domain_record[dn] += [getattr(dnslib, typ)(getattr(DOMAIN, v)) for v in value]
        elif typ in ['TXT']:
            for name, value in records.items():
                dn = getattr(DOMAIN, name)
                domain_record[dn] = [getattr(dnslib, typ)(value)]
        elif typ in ['SRV']:
            for name, value in records.items():
                dn = getattr(DOMAIN, name)
                if dn not in domain_record:
                    domain_record[dn] = []
                for v in value:
                    v = v.split(' ')
                    domain_record[dn].append(getattr(dnslib, typ)(
                        priority=int(v[0]),
                        weight=int(v[1]),
                        port=int(v[2]),
                        target=getattr(DOMAIN, v[3])
                    ))
        else:
            logger.warn('DNS domain_record %s(%s) need to be handled...' % (typ, name))
    return config


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', action='version',
                        version='%%(prog)s %s' % __version__)
    parser.add_argument('-v', '--verbose', help='verbose help',
                        action='count', default=0)
    parser.add_argument(
        '--config',
        help='read config from file',
        default='homedns.json',
    )
    args = parser.parse_args()

    global config
    config = init_config(args.config)

    __log_level__ = config['log']['level']
    __log_file__ = config['log']['file']

    if args.verbose > 0:
        __log_level__ = logging.WARNING - (args.verbose * 10)

    if __log_level__ <= logging.DEBUG:
        formatter = '[%(levelname)s] [%(name)s %(lineno)d] %(message)s'
    else:
        formatter = '%(message)s'

    if args.verbose > 0:
        logging.basicConfig(
            format=formatter,
            level=__log_level__,
        )
    else:
        logging.basicConfig(
            filename=__log_file__,
            format=formatter,
            level=__log_level__,
        )

    logger.debug('Config: %s', config)
    logger.debug('Domain Record:')
    for name, rrs in local_domain['record'].iteritems():
        logger.debug('%s => %s' % (
            name,
            ', '.join(['%s(%s)' % (rdata.__class__.__name__, rdata) for rdata in rrs]),
        ))

    logger.info("Starting nameserver...")

    ip = config['server']['listen_ip']
    port = config['server']['listen_port']

    logger.info('Listen on %s:%s' % (ip, port))

    servers = []
    if 'udp' in config['server']['protocols']:
        servers.append(
            SocketServer.ThreadingUDPServer((ip, port), UDPRequestHandler)
        )
    if 'tcp' in config['server']['protocols']:
        servers.append(
            SocketServer.ThreadingTCPServer((ip, port), TCPRequestHandler),
        )

    for s in servers:
        thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
        logger.info( "%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name))

    try:
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()

if __name__ == '__main__':
    run()
