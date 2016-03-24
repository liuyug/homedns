#!/usr/bin/env python
# -*- encoding:utf-8 -*-

import socket
import struct
import random
import binascii
import logging


logger = logging.getLogger(__name__)


class DHCPType(object):
    def __init__(self, forward, formatter=None):
        self.forward = dict(forward)
        self.reverse = dict(zip(self.forward.values(), self.forward.keys()))
        self.reverse['formatter'] = formatter or {}

    def get(self, item):
        value = self.reverse.get(item)
        if not value:
            value = item
        return value

    def __getitem__(self, item):
        return self.get(item)

    def __contains__(self, item):
        return item in self.reverse

    def __getattr__(self, item):
        return self.forward.get(item)


class BootOPCode():
    request = 1
    reply = 2


class HardwareType():
    ethernet = 1


class MessageType():
    discover = 1
    offer = 2
    request = 3
    decline = 4
    ack = 5
    nack = 6
    release = 7


Option = DHCPType(
    (
        ('pad', 0),
        ('subnet_mask', 1),
        ('router', 3),
        ('name_server', 5),
        ('domain_name_server', 6),
        ('host_name', 12),
        ('domain_name', 15),
        ('ip_address_lease_time', 51),
        ('message_type', 53),
        ('server_identifier', 54),
        ('parameter_request_list', 55),
        ('private_use_252', 252),
        ('end', 255),
    ),
    formatter={
        0: ('B', 1, ''),
        1: ('4s', 4, 'ipv4'),
        3: ('4s', 4, 'ipv4'),
        5: ('4s', 4, 'ipv4'),
        6: ('4s', 4, 'ipv4'),
        12: ('s', 1, 'str'),
        15: ('s', 1, 'str'),
        51: ('L', 4, 'int'),
        53: ('B', 1, 'int'),
        54: ('4s', 4, 'ipv4'),
        55: ('B', 1, 'list'),
        252: ('B', 1, ''),
        255: ('B', 1, ''),
    }
)


class DHCPPacket(object):
    op = BootOPCode.request
    htype = HardwareType.ethernet
    hlen = 0x06
    hops = 0x00
    xid = None
    secs = 0x0000
    flags = 0x0000
    ciaddr = None
    yiaddr = None
    siaddr = None
    giaddr = None
    chaddr = None
    sname = ''
    bfile = ''
    magic_cookie = b'\x63\x82\x53\x63'
    options = None

    def __init__(
            self, mtype, hwaddr=None, xid=None,
            ciaddr=None, yiaddr=None, siaddr=None, giaddr=None,
            sname=None, bfile=None):
        self.options = {}
        self.options[Option.message_type] = struct.pack('B', mtype)
        if mtype in [MessageType.discover]:
            self.flags = 0x8000
            self.options[Option.parameter_request_list] = struct.pack(
                '>2B',
                Option.domain_name_server,
                Option.domain_name,
            )
        if mtype in [MessageType.offer, MessageType.ack, MessageType.nack]:
            self.op = BootOPCode.reply
        else:
            self.op = BootOPCode.request
        self.xid = xid or random.randint(1, 0xffffffff)
        self.chaddr = hwaddr or '00:00:00:00:00:00'
        self.ciaddr = ciaddr or '0.0.0.0'
        self.yiaddr = yiaddr or '0.0.0.0'
        self.siaddr = siaddr or '0.0.0.0'
        self.giaddr = giaddr or '0.0.0.0'
        self.sname = sname or ''
        self.bfile = bfile or ''

    def __str__(self):
        line = []
        line.append('op: %s' % hex(self.op))
        line.append('htype: %s' % hex(self.htype))
        line.append('hlen: %s' % hex(self.hlen))
        line.append('hops: %s' % hex(self.hops))
        line.append('xid: %s' % hex(self.xid))
        line.append('secs: %s' % self.secs)
        line.append('flags: %s' % hex(self.flags))
        line.append('ciaddr: %s' % self.ciaddr)
        line.append('yiaddr: %s' % self.yiaddr)
        line.append('siaddr: %s' % self.siaddr)
        line.append('giaddr: %s' % self.giaddr)
        line.append('sname: %s' % self.sname)
        line.append('bfile: %s' % self.bfile)
        value, = struct.unpack('>L', self.magic_cookie)
        line.append('magic_cookie: %s' % hex(value))
        line.append('options:')
        for k in self.options.keys():
            value = self.getfmtopt(k, self.options)
            line.append('\t%s: %s' % (Option[k], value))
        return '\n'.join(line)

    @classmethod
    def getfmtopt(cls, code, options):
        fmt = Option['formatter'].get(code)
        if not fmt:
            return options[code]
        length = len(options[code])
        values = []
        for x in range(0, length, fmt[1]):
            v, = struct.unpack('>%s' % fmt[0], options[code][x:x + fmt[1]])
            if fmt[2] == 'ipv4':
                values.append(socket.inet_ntoa(v))
            else:
                values.append(v)
        if fmt[2] == 'str':
            values = [b''.join(values).decode('ascii')]
        return values

    @classmethod
    def parse(cls, data):
        magic_offset = data.find(cls.magic_cookie)
        if magic_offset < 0:
            raise ValueError('could not find magic cookie')
        offset = magic_offset + 4
        max_length = len(data)
        options = {}
        while True:
            code = data[offset]
            if code == Option.end:
                break
            if code == Option.pad:
                offset += 1
                continue
            length = data[offset + 1]
            offset += 2
            value = data[offset:offset + length]
            value = data[offset:offset + length]
            options[code] = value
            if code not in Option:
                logger.error('Not handle: %s: %s' % (code, value))
            offset += length
            if offset > max_length:
                raise ValueError('Not engough dhcp data')

        mtype, = cls.getfmtopt(Option.message_type, options)
        op, htype, hlen, hops,  \
            xid,    \
            secs, flags,    \
            ciaddr, \
            yiaddr, \
            siaddr, \
            giaddr, \
            hwaddr, \
            = struct.unpack('>4BL2H4s4s4s4s6s10x', data[:44])
        hwaddr = binascii.b2a_hex(hwaddr).decode('ascii')
        hwaddr = ':'.join([hwaddr[x:x + 2] for x in range(0, 12, 2)])
        instance = cls(
            mtype,
            xid=xid,
            ciaddr=socket.inet_ntoa(ciaddr),
            yiaddr=socket.inet_ntoa(yiaddr),
            siaddr=socket.inet_ntoa(siaddr),
            giaddr=socket.inet_ntoa(giaddr),
            hwaddr=hwaddr,
        )
        instance.op = op
        instance.htype = htype
        instance.hlen = hlen
        instance.hops = hops
        instance.secs = secs
        instance.flags = flags

        offset = 44
        if (offset + 64) <= magic_offset:
            sname, = struct.unpack('>64s', data[offset:offset + 64])
            instance.sname = sname.strip(b'\x00').decode('ascii')
        else:
            raise ValueError('not enough data for sname')
        offset += 64
        if (offset + 128) <= magic_offset:
            bfile, = struct.unpack('>128s', data[offset:offset + 128])
            instance.bfile = bfile.strip(b'\x00').decode('ascii')
        else:
            raise ValueError('not enough data for bfile')
        instance.options = options
        return instance

    def pack(self):
        message = struct.pack(
            '>4BL2H4s4s4s4s',
            self.op, self.htype, self.hlen, self.hops,
            self.xid,
            self.secs, self.flags,
            socket.inet_aton(self.ciaddr),
            socket.inet_aton(self.yiaddr),
            socket.inet_aton(self.siaddr),
            socket.inet_aton(self.giaddr),
        )
        message += binascii.a2b_hex(self.chaddr.replace(':', '').encode('ascii'))
        # padding for hardware address
        message += b'\x00' * 10
        message += struct.pack('>64s', self.sname.encode('ascii'))
        message += struct.pack('>128s', self.bfile.encode('ascii'))
        message += self.magic_cookie
        options = b''
        for k, v in self.options.items():
            options += struct.pack('>2B', k, len(v))
            options += v
        options += struct.pack('>2B', Option.end, 0x00)
        # align to word
        options += (struct.pack('>B', Option.pad) * (len(options) % 4))
        return message + options
