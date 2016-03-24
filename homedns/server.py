#!/usr/bin/env python
# -*- encoding:utf-8 -*-

import datetime
import binascii
import logging
import logging.handlers
import socket
import struct
import traceback

import socks
from dnslib import RR, QTYPE, DNSRecord, DNSHeader, DNSLabel

from . import py_version, globalvars

if py_version == 3:
    import socketserver
elif py_version == 2:
    import SocketServer as socketserver


logger = logging.getLogger(__name__)


class BaseRequestHandler(socketserver.BaseRequestHandler):

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        logger.debug('%s REQUEST %s' % ('=' * 35, '=' * 36))
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        client_ip = self.client_address[0]
        client_port = self.client_address[1]
        logger.info("%s request %s (%s %s):" % (
            self.__class__.__name__[:3],
            now,
            client_ip, client_port,
        ))
        if client_ip not in globalvars.allowed_hosts:
            logger.warn('\t*** Not allowed host: %s ***' % client_ip)
            return
        try:
            data = self.get_data()
            logger.debug('%s %s' % (len(data), binascii.b2a_hex(data)))
            dns_response(self, data)
        except Exception as err:
            traceback.print_exc()
            logger.error('send data: %s' % (err))


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
    for value in globalvars.local_domains.values():
        domain = value['domain']
        if globalvars.config['smartdns']['hack_srv'] and qt == 'SRV' and \
                not domain.inDomain(qn2):
            r_srv = b'.'.join(qn.label[:2])
            if r_srv.decode().lower() in globalvars.config['smartdns']['hack_srv']:
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
            logger.info('\tReturn from LOCAL:\n%s' % '\n'.join(lines))
            logger.debug('\n' + str(reply))
        else:
            logger.info('\tReturn from LOCAL: N/A')
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
            logger.info(message)
        else:
            sock = socket.socket(inet, stype)
            message = '\tForward to server %s:%s with %s mode' % (
                dest, port,
                'TCP' if tcp else 'UDP',
            )
            logger.info(message)
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
                logger.info('\tReturn from %s:%s:\n%s' % (
                    server['ip'], server['port'],
                    '\n'.join(lines)
                ))
                logger.debug('\n' + str(reply))
                handler.send_data(reply.pack())
        except socket.error as err:
            frm = '%s:%s' % (server['ip'], server['port'])
            if server['proxy']:
                frm += ' (with proxy %(ip)s:%(port)s)' % proxy
            logger.error('\tError when lookup from %s: %s' % (frm, err))
        except Exception as err:
            if logger.isEnabledFor(logging.DEBUG):
                traceback.print_exc()
            frm = '%s:%s' % (server['ip'], server['port'])
            logger.error('\tError when lookup from %s: %s' % (frm, err))
        queue.task_done()


def dns_response(handler, data):
    try:
        request = DNSRecord.parse(data)
    except Exception as err:
        logger.error('Parse request error: %s' % err)
        return
    qn = request.q.qname
    qt = QTYPE[request.q.qtype]
    logger.info('\tRequest: %s(%s)' % (qn, qt))
    logger.debug('\n' + str(request))

    local = False
    if 'local' in globalvars.config['server']['search']:
        local = lookup_local(handler, request)
    if not local and 'upstream' in globalvars.config['server']['search']:
        qn2 = str(qn).rstrip('.')
        for name, param in globalvars.rules.items():
            if param['rule'].isBlock(qn2):
                logger.warn('\tRequest(%s) is in "%s" list.' % (qn, name))
                for dns in param['upstreams']:
                    for value in dns:
                        value['queue'].put((handler, request))
                        value['count'] += 1
                break
    # update
    for value in globalvars.rules.values():
        rule = value['rule']
        if rule.isNeedUpdate(value['refresh']):
            rule.async_update()
    for value in globalvars.local_domains.values():
        domain = value['domain']
        if domain.isNeedUpdate(value['refresh']):
            domain.async_update()
