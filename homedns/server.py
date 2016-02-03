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
import traceback
try:
    import socketserver
except:
    import SocketServer as socketserver

import socks
import netaddr
from dnslib import RR, QTYPE, DNSRecord, DNSHeader

from .domain import Domain, HostDomain
from .adblock import Adblock, ABTYPE

__version__ = '0.1.5'


logger = logging.getLogger(__name__)


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
            traceback.print_exc()
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

    is_local = False
    for domain in local_domains:
        if not domain.inDomain(qn):
            continue
        is_local = True
        rr_data = domain.search(qn, qt)
        for r in rr_data:
            answer = RR(
                rname=qn,
                rtype=getattr(QTYPE, r['type']),
                rclass=1, ttl=60 * 5,
                rdata=r['rdata'],
            )
            reply.add_answer(answer)

    if is_local:
        if reply.rr:
            lines = []
            for r in reply.rr:
                rqn = r.rdata
                rqt = QTYPE[r.rtype]
                lines.append('\t\t%s(%s)' % (rqn, rqt))
            logger.warn('\tFrom LOCAL return:\n%s' % '\n'.join(lines))
            logger.info(reply)
        else:
            logger.warn('\tFrom LOCAL return: N/A')
        handler.send_data(reply.pack())
    return is_local


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
                socks.PROXY_TYPES[proxy['type'].upper()],
                proxy['ip'],
                proxy['port'],
            )
            message = '\tForward to server %s:%s' % (dest, port)
            message += ' with proxy %(type)s://%(ip)s:%(port)s' % proxy
            logger.warn(message)
        else:
            sock = socket.socket(inet, stype)
        return sock

    if ipv6:
        inet = socket.AF_INET6
    else:
        inet = socket.AF_INET
    if not tcp and proxy and proxy['enable']:
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


def lookup_upstream_worker(queue, server, proxy=None):
    """
    If smartdns enable
    forward request to dns server through proxy by rule
    or
    forward request to all dns servers
    """
    while True:
        handler, request = queue.get()
        try:
            if config['smartdns']['enable']:
                qn = str(request.q.qname).rstrip('.')
                qn_type = ABTYPE['unknown']
                for bw in bw_list:
                    qn_type = bw.inList(qn)
                    if qn_type != ABTYPE['unknown']:
                        break

                smart_proxy = proxy.copy()
                if qn_type == ABTYPE[server['type']] or \
                        (qn_type == ABTYPE['unknown'] and
                         ABTYPE[server['type']] == ABTYPE['white']):
                    smart_proxy['enable'] = qn_type == ABTYPE['black']
                    logger.warn('\tRequest "%s" is in "%s" list.' % (
                        qn,
                        ABTYPE.get_desc(qn_type),
                    ))
                    r_data = do_lookup_upstream(
                        request.pack(),
                        server['ip'],
                        server['port'],
                        tcp=server['tcp'],
                        timeout=server['timeout'],
                        proxy=smart_proxy,
                    )
                    reply = DNSRecord.parse(r_data)
                else:
                    reply = DNSRecord(
                        DNSHeader(id=request.header.id, qr=1, aa=1, ra=1),
                        q=request.q
                    )
            else:
                r_data = do_lookup_upstream(
                    request.pack(),
                    server['ip'],
                    server['port'],
                    tcp=server['tcp'],
                    timeout=server['timeout'],
                    proxy=proxy,
                )
                reply = DNSRecord.parse(r_data)
            if reply.rr:
                lines = []
                for r in reply.rr:
                    rqn = r.rdata
                    rqt = QTYPE[r.rtype]
                    lines.append('\t\t%s(%s)' % (rqn, rqt))
                logger.warn('\tFrom %s:%s return:\n%s' % (
                    server['ip'], server['port'],
                    '\n'.join(lines)
                ))
                logger.info(reply)
                handler.send_data(reply.pack())
        except Exception as err:
            if logger.isEnabledFor(logging.DEBUG):
                traceback.print_exc()
            logger.fatal('\tError when lookup from %s:%s: %s' % (
                server['ip'], server['port'],
                err,
            ))
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
    import default
    global config
    global local_domains
    global allowed_hosts
    global upstreams
    global bw_list
    if os.path.exists(config_file):
        config = json.load(open(config_file))
    else:
        config = {
            'log': default.log,
            'server': default.server,
            'smartdns': default.smartdns,
            'domain': default.domain,
        }
        json.dump(config, open(config_file, 'w'), indent=4)
    config_dir = os.path.dirname(config_file)

    bw_list = []
    if config['smartdns']['enable']:
        for rule in config['smartdns']['rules']:
            rule_file = os.path.join(config_dir, rule)
            if os.path.exists(rule_file):
                ab = Adblock(rule_file)
                bw_list.append(ab)

    upstreams = []
    for upstream in config['smartdns']['upstreams']:
        q = Queue()
        t = threading.Thread(
            target=lookup_upstream_worker,
            args=(q, upstream),
            kwargs={
                'proxy': config['smartdns']['proxy'],
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
    hosts_file = os.path.join(config_dir, 'hosts')
    if os.path.exists(hosts_file):
        host = HostDomain('hosts')
        host.create(open(hosts_file))
        local_domains.append(host)

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
