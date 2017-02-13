#!/usr/bin/env python
# -*- encoding:utf-8 -*-

import datetime
import binascii
import logging
import logging.handlers
import socket
import struct
import traceback

from six.moves import socketserver
import socks
import dnslib
from dnslib import RR, QTYPE, DNSRecord, DNSHeader, DNSLabel

from . import globalvars


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
        logger.warn("\n%s request %s (%s %s):" % (
            self.__class__.__name__[:3],
            now,
            client_ip, client_port,
        ))
        if client_ip not in globalvars.allowed_hosts:
            logger.warn('\t*** Not allowed host: %s ***' % client_ip)
            return
        try:
            data = self.get_data()
            dns_response(self, data)
        except Exception as err:
            traceback.print_exc()
            logger.error('send data: %s' % (err))


class TCPRequestHandler(BaseRequestHandler):

    def get_data(self):
        data = self.request.recv(8192)
        sz = int(binascii.b2a_hex(data[:2]), 16)
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        logger.debug('%s %s' % (len(data), binascii.b2a_hex(data[2:])))
        return data[2:]

    def send_data(self, data):
        sz = bytes(binascii.a2b_hex(hex(len(data))[2:].zfill(4)))
        logger.debug('%s %s' % (len(data), binascii.b2a_hex(data)))
        return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandler):

    def get_data(self):
        data = self.request[0]
        logger.debug('%s %s' % (len(data), binascii.b2a_hex(data)))
        return data

    def send_data(self, data):
        logger.debug('%s %s' % (len(data), binascii.b2a_hex(data)))
        return self.request[1].sendto(data, self.client_address)


def lookup_local(request, reply):
    qn2 = qn = request.q.qname
    qt = QTYPE[request.q.qtype]

    indomain = False

    for value in globalvars.local_domains.values():
        domain = value['domain']
        if globalvars.config['smartdns']['hack_srv'] and qt == 'SRV' and \
                not domain.inDomain(qn2):
            r_srv = b'.'.join(qn.label[:2])
            if r_srv.decode().lower() in globalvars.config['smartdns']['hack_srv']:
                qn2 = DNSLabel(domain.get_subdomain('@')).add(r_srv)
                logger.warn('\tChange SRV request to %s from %s' % (qn2, qn))

        if domain.inDomain(qn2):
            indomain = True
            logger.warn('\tRequest "%s(%s)" is in "local" list.' % (qn, qt))
            rr_data = domain.search(qn2, qt)
            if rr_data:
                for r in rr_data:
                    answer = RR(
                        rname=r['name'],
                        rtype=getattr(QTYPE, r['type']),
                        rclass=1, ttl=60 * 5,
                        rdata=r['rdata'],
                    )
                    reply.add_answer(answer)

                    if r['type'] == 'CNAME' and not domain.inDomain(r['rdata'].get_label()):
                        logger.warn('\tOutside alias "%s"' % r['rdata'])
                        alias_request = DNSRecord.question(str(r['rdata']))
                        alias_reply = DNSRecord(
                            DNSHeader(id=alias_request.header.id, qr=1, aa=1, ra=1),
                            q=alias_request.q
                        )
                        lookup_upstream(alias_request, alias_reply)
                        for r in alias_reply.rr:
                            reply.add_answer(r)
                break

    # log
    if indomain:
        logger.warn('\tReturn from LOCAL:')
        if globalvars.dig:
            logger.warn(str(reply))
        elif reply.rr:
            for r in reply.rr:
                logger.warn('\t\t%s(%s)' % (r.rdata, QTYPE[r.rtype]))
        else:
            logger.warn('\tReturn: \n\t\tN/A')

    return indomain


def sendto_upstream(data, dest, port=53,
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
        else:
            sock = socket.socket(inet, stype)
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
        if response:
            length = struct.unpack("!H", bytes(response[:2]))[0]
            while len(response) - 2 < length:
                response += sock.recv(8192)
            response = response[2:]
        sock.close()
    else:
        if timeout is not None:
            sock.settimeout(timeout)
        sock.sendto(data, (dest, port))
        response, server = sock.recvfrom(8192)
        sock.close()
    return response


def lookup_upstream_by_server(request, reply, server, proxy):
    """
    use TCP mode when proxy enable
    """
    try:
        message = '\tForward to server %(ip)s:%(port)s(%(priority)s)' % server
        message += ' with %s mode' % ('TCP' if server['tcp'] else 'UDP')
        if server['proxy'] and proxy:
                message += ' and proxy %(type)s://%(ip)s:%(port)s' % proxy
        logger.info(message)

        data = sendto_upstream(
            request.pack(),
            server['ip'],
            server['port'],
            tcp=server['tcp'],
            timeout=server['timeout'],
            proxy=proxy if server['proxy'] else None,
        )
        try:
            upstream_reply = DNSRecord.parse(data)
        except Exception as err:
            logger.error('Parse request error: %s %s %s' % (
                err, len(data), binascii.b2a_hex(data)))
            return
        if upstream_reply.rr:
            for r in upstream_reply.rr:
                rqn = r.rname
                rqt = QTYPE[r.rtype]
                if rqt in ['A', 'AAAA'] and str(r.rdata) in globalvars.bogus_nxdomain:
                    logger.warn('\t*** Bogus Answer: %s(%s) ***' % (r.rdata, rqt))
                    hack_ip = globalvars.config['smartdns']['bogus_nxdomain']['hack_ip']
                    if hack_ip:
                        hack_rqt = 'AAAA' if ':' in hack_ip else 'A'
                        hack_r = RR(
                            rname=rqn,
                            rtype=getattr(QTYPE, hack_rqt),
                            rclass=1, ttl=60 * 5,
                            rdata=getattr(dnslib, hack_rqt)(hack_ip),
                        )
                        reply.rr.append(hack_r)
                else:
                    reply.add_answer(r)

        logger.warn('\tReturn from %(ip)s:%(port)s:' % server)
        if globalvars.dig:
            logger.warn(str(reply))
        elif reply.rr:
            for r in reply.rr:
                logger.warn('\t\t%s(%s)' % (r.rdata, QTYPE[r.rtype]))
        else:
            logger.warn('\n\t\tN/A')
    except socket.error as err:
        frm = '%(ip)s:%(port)s(%(priority)s)' % server
        if server['proxy']:
            frm += ' (with proxy %(ip)s:%(port)s)' % proxy
        logger.error('\tError when lookup from %s: %s' % (frm, err))
    except Exception as err:
        if logger.isEnabledFor(logging.DEBUG):
            traceback.print_exc()
        frm = '%(ip)s:%(port)s(%(priority)s)' % server
        logger.error('\tError when lookup from %s: %s' % (frm, err))
    return


def lookup_upstream(request, reply):
    qn = request.q.qname
    qt = QTYPE[request.q.qtype]
    proxy = globalvars.config['smartdns']['proxy']
    qn2 = str(qn).rstrip('.')

    for name, param in globalvars.rules.items():
        if param['rule'].isBlock(qn2):
            logger.warn('\tRequest "%s(%s)" is in "%s" list.' % (qn, qt, name))
            best_dns = None
            servers = []
            for group in param['upstreams']:
                servers.extend(globalvars.upstreams[group])
            for server in servers:
                if best_dns is None:
                    best_dns = server
                elif best_dns['priority'] < server['priority']:
                    best_dns = server
            lookup_upstream_by_server(request, reply, best_dns, proxy)

            if reply.rr:
                best_dns['priority'] += (5 if best_dns['priority'] < 100 else 0)
            else:
                best_dns['priority'] += (-10 if best_dns['priority'] > 0 else -1)

            # only use first matching rule
            break
    return


def dns_response(handler, data):
    try:
        request = DNSRecord.parse(data)
    except Exception as err:
        logger.error('Parse request error: %s %s %s' % (
            err, len(data), binascii.b2a_hex(data)))
        return

    reply = DNSRecord(
        DNSHeader(id=request.header.id, qr=1, aa=1, ra=1),
        q=request.q
    )

    if 'local' in globalvars.config['server']['search']:
        indomain = lookup_local(request, reply)
    if not indomain and 'upstream' in globalvars.config['server']['search']:
        lookup_upstream(request, reply)

    handler.send_data(reply.pack())

    # update
    for value in globalvars.rules.values():
        rule = value['rule']
        if rule.isNeedUpdate(value['refresh']):
            rule.async_update()
    for value in globalvars.local_domains.values():
        domain = value['domain']
        if domain.isNeedUpdate(value['refresh']):
            domain.async_update()
