#!/usr/bin/env python
# -*- encoding:utf-8 -*-

import binascii
import socket
import logging
import time

from .packet import DHCPPacket, MessageType, Option
from ..interface import Interface

logger = logging.getLogger(__name__)


class DHCPClient():
    server_addr = ('255.255.255.255', 67)
    client_addr = ('0.0.0.0', 68)
    sock = None

    def __init__(self, timeout=10):
        self.create(timeout=timeout)

    def create(self, timeout=10):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

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

    def close(self):
        self.sock.close()


def getdns(iface=None, retry=1):
    interface = Interface()
    if not iface:
        iface = interface.gateway_iface
    iface_info = interface.interfaces.get(iface)
    if not iface_info:
        return []
    logger.warn('\tDHCP interface: %s - %s (%s)' % (
        iface,
        iface_info['ipaddr'][0],
        iface_info['macaddr'],
    ))

    client = DHCPClient()
    client.bindif(addr=iface_info['ipaddr'][0])
    request = DHCPPacket(
        MessageType.discover,
        hwaddr=iface_info['macaddr'],
    )
    s_data = request.pack()
    logger.debug('send %s %s' % (len(s_data), binascii.b2a_hex(s_data)))
    count = 0
    sleep = 5
    while True:
        try:
            r_data = client.send(s_data)
            client.close()
            break
        except socket.error as err:
            logger.error('getdns error: %s' % err)
            if count >= retry:
                return []
            count += 1
            logger.warn('Wait %s seconds to retry...(%s)' % (sleep, count))
            time.sleep(sleep)
    logger.debug('recv %s %s' % (len(r_data), binascii.b2a_hex(r_data)))
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
        interface = Interface()
        for iface in interface.interfaces.keys():
            print(iface)
    elif args.dhcp:
        getdns(args.iface)
    else:
        parser.print_help()
