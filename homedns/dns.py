import logging
import binascii
import struct
import socket
import traceback

import dnslib
from dnslib import RR, QTYPE, DNSRecord
import socks

from . import globalvars

logger = logging.getLogger(__name__)


def lookup_upstream(request, reply, server, proxy):
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
            return True
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
        message = ['\tReturn from %(ip)s:%(port)s(%(priority)s):' % server]
        if globalvars.dig:
            logger.warn(str(reply))
        elif reply.rr:
            for r in reply.rr:
                message.append('\t\t%s(%s)' % (r.rdata, QTYPE[r.rtype]))
        else:
            message.append('\t\tN/A')
        logger.warn('\n'.join(message))
        return True
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
    return False


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
