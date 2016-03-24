#!/usr/bin/env python
# -*- encoding:utf-8 -*-

import binascii
import socket
import logging

from .packet import DHCPPacket, MessageType, Option
from .utils import getifaddrs, getdefaultiface, getifaces

logger = logging.getLogger(__name__)


class Client():
    server_addr = ('255.255.255.255', 67)
    client_addr = ('0.0.0.0', 68)
    sock = None

    def __init__(self, timeout=5):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    def bindif(self, addr=None, iface=None):
        if addr:
            self.sock.bind((addr, 68))
        elif iface:
            SO_BINDTODEVICE = 25
            send_face = iface.encode('ascii') + b'\x00'
            self.sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, send_face)
            self.sock.bind(self.client_addr)

    def send(self, data, addr=None):
        if not addr:
            addr = self.server_addr
        self.sock.sendto(data, addr)
        response, server = self.sock.recvfrom(8192)
        return response


def getdns(iface=None):
    if not iface:
        iface = getdefaultiface()
    addrs = getifaddrs(iface)
    client = Client()
    client.bindif(addr=addrs['AF_INET'][0]['addr'])

    request = DHCPPacket(
        MessageType.discover,
        hwaddr=addrs['AF_LINK'][0]['addr'],
    )
    logger.debug('use interface: %s - %s (%s)' % (
        iface,
        addrs['AF_INET'][0]['addr'],
        addrs['AF_LINK'][0]['addr'],
    ))
    s_data = request.pack()
    logger.debug('send %s %s' % (hex(len(s_data)), binascii.b2a_hex(s_data)))
    r_data = client.send(s_data)
    logger.debug('recv %s %s' % (hex(len(r_data)), binascii.b2a_hex(r_data)))
    response = DHCPPacket.parse(r_data)
    logger.debug(response)
    return response.getfmtopt(Option.domain_name_server, response.options)

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-L', dest='ifaces', action='store_true', help='list all interfaces')
    parser.add_argument('--iface', help='Use interface')
    parser.add_argument('-d', dest='dhcp', action='store_true', help='get dhcp configuartion')

    args = parser.parse_args()

    logging.basicConfig(format='%(message)s', level=logging.DEBUG)

    if args.ifaces:
        ifaces = getifaces()
        count = 0
        for iface in ifaces:
            addrs = []
            for k, v in getifaddrs(iface).items():
                if k in ['AF_INET', 'AF_INET6']:
                    addrs.append(v[0]['addr'])
            print('%2d %s: %s' % (count, iface, addrs))
            count += 1
    elif args.dhcp:
        getdns(args.iface)
    else:
        parser.print_help()
