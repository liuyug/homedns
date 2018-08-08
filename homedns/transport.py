#!/usr/bin/env python
# -*- encoding:utf-8 -*-

import datetime
import binascii
import logging
import logging.handlers
import traceback

import socketserver

from . import globalvars
from . import lookup

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
            lookup.dns_response(self, data)
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
