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
from collections import OrderedDict
try:
    import socketserver
except:
    import SocketServer as socketserver

import socks
import netaddr
from dnslib import RR, QTYPE, DNSRecord, DNSHeader, DNSLabel

from .domain import Domain, HostDomain
from .adblock import Adblock

__version__ = '0.1.10'


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
    qn2 = qn = request.q.qname
    qt = QTYPE[request.q.qtype]

    reply = DNSRecord(
        DNSHeader(id=request.header.id, qr=1, aa=1, ra=1),
        q=request.q
    )

    is_local = False
    for domain in local_domains:
        if config['smartdns']['hack_srv'] and qt == 'SRV' and \
                not domain.inDomain(qn2):
            r_srv = '.'.join(qn.label[:2])
            if r_srv in config['smartdns']['hack_srv']:
                qn2 = DNSLabel(domain.get_subdomain('@')).add(r_srv)
                logger.warn('\tChange SRV request to %s from %s' % (qn2, qn))

        if domain.inDomain(qn2):
            is_local = True
            rr_data = domain.search(qn2, qt)
            for r in rr_data:
                answer = RR(
                    rname=qn,
                    rtype=getattr(QTYPE, r['type']),
                    rclass=1, ttl=60 * 5,
                    rdata=r['rdata'],
                )
                reply.add_answer(answer)
            if reply.rr:
                break

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
    def get_sock(inet, tcp, proxy=None):
        stype = socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM
        if tcp and proxy:
            sock = socks.socksocket(inet, stype)
            sock.set_proxy(
                socks.PROXY_TYPES[proxy['type'].upper()],
                proxy['ip'],
                proxy['port'],
            )
            message = '\tForward to server %s:%s with TCP mode' % (dest, port)
            message += ' and proxy %(type)s://%(ip)s:%(port)s' % proxy
            logger.warn(message)
        else:
            sock = socket.socket(inet, stype)
            message = '\tForward to server %s:%s with %s mode' % (
                dest, port,
                'TCP' if tcp else 'UDP',
            )
            logger.warn(message)
        return sock

    if ipv6:
        inet = socket.AF_INET6
    else:
        inet = socket.AF_INET

    sock = get_sock(inet, tcp, proxy)
    if tcp:
        if len(data) > 65535:
            raise ValueError("Packet length too long: %d" % len(data))
        data = struct.pack("!H", len(data)) + data
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
        if timeout is not None:
            sock.settimeout(timeout)
        sock.sendto(data, (dest, port))
        response, server = sock.recvfrom(8192)
        sock.close()
    return response


def lookup_upstream_worker(queue, server, proxy=None):
    """
    use TCP mode when proxy enable
    """
    while True:
        handler, request = queue.get()
        try:
            r_data = do_lookup_upstream(
                request.pack(),
                server['ip'],
                server['port'],
                tcp=server['proxy'],
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
    if 'local' in config['server']['search']:
        found = lookup_local(handler, request)
    if not found and 'upstream' in config['server']['search']:
        qn2 = str(qn).rstrip('.')
        for name, param in rules.items():
            if param['rule'].isBlock(qn2):
                logger.warn('\tRequest(%s) is in "%s" list.' % (qn, name))
                for t, q in param['upstreams']:
                    q.put((handler, request))
                break


def init_config(config_file):
    import default
    global config
    global local_domains
    global allowed_hosts
    global rules
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

    rules = OrderedDict()
    for name in config['smartdns']['rules']:
        rule_file = os.path.join(config_dir, name + '.rules')
        if os.path.exists(rule_file):
            ab = Adblock(open(rule_file))
            rules[name] = {
                'rule': ab,
                'upstreams': [],
            }

    proxy = config['smartdns']['proxy']
    for upstream in config['smartdns']['upstreams']:
        if upstream['rule'] in rules:
            q = Queue()
            t = threading.Thread(
                target=lookup_upstream_worker,
                args=(q, upstream),
                kwargs={
                    'proxy': proxy if upstream['proxy'] else None
                }
            )
            t.daemon = True
            t.start()
            rules[upstream['rule']]['upstreams'].append((t, q))

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
    hosts_file = os.path.join(config_dir, 'hosts.homedns')
    if os.path.exists(hosts_file):
        host = HostDomain('home.dns')
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
    for domain in local_domains:
        logger.debug('Domain "%s" records:' % domain)
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
