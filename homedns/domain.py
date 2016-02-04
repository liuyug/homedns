#!/usr/bin/env python
# -*- encoding:utf-8 -*-

# local domain

import logging

import netaddr
import dnslib


logger = logging.getLogger(__name__)


class Domain(object):
    """
    @:    current domain
    """
    def __init__(self, name):
        self.name = name + '.'
        self.ptr_records = {}
        self.records = {}

    def __repr__(self):
        return '<Domain: %s>' % self.name

    def __bool__(self):
        return bool(self.records)

    def create(self, data):
        for typ, records in data.items():
            if typ in ['SOA']:
                dn = self.get_subdomain('@')
                self.records[dn] += [getattr(dnslib, typ)(
                    mname=self.get_subdomain(records['mname']),
                    rname=self.get_subdomain(records['rname']),
                    times=(
                        records['serial'],
                        records['refresh'],
                        records['retry'],
                        records['expire'],
                        records['minimum'],
                    )
                )]
            elif typ in ['NS', 'MX']:
                dn = self.get_subdomain('@')
                self.records[dn] += [
                    getattr(dnslib, typ)(self.get_subdomain(v)) for v in records
                ]
            elif typ in ['A', 'AAAA']:
                for name, value in records.items():
                    dn = self.get_subdomain(name)
                    for v in value:
                        self.records[dn] += [getattr(dnslib, typ)(v)]
                        # add ptr
                        ptr_dn = self.get_ptrdomain(v)
                        self.ptr_records[ptr_dn] += [
                            dnslib.PTR(self.get_subdomain(name))
                        ]
            elif typ in ['TXT']:
                for name, value in records.items():
                    dn = self.get_subdomain(name)
                    self.records[dn] += [getattr(dnslib, typ)(v) for v in value]
            elif typ in ['CNAME']:
                for name, value in records.items():
                    dn = self.get_subdomain(name)
                    self.records[dn] += [
                        getattr(dnslib, typ)(self.get_subdomain(v)) for v in value
                    ]
            elif typ in ['PTR']:
                for name, value in records.items():
                    dn = self.get_ptrdomain(name)
                    self.ptr_records[dn] += [
                        getattr(dnslib, typ)(self.get_subdomain(v)) for v in value
                    ]
            elif typ in ['SRV']:
                for name, value in records.items():
                    dn = self.get_subdomain(name)
                    for v in value:
                        v = v.split(' ')
                        self.records[dn].append(getattr(dnslib, typ)(
                            priority=int(v[0]),
                            weight=int(v[1]),
                            port=int(v[2]),
                            target=self.get_subdomain(v[3])
                        ))
            else:
                logger.warn('DNS Record %s(%s) need to be handled...' % (typ, name))

    def get_subdomain(self, subname):
        if subname == '@':
            dn = self.name
        else:
            dn = subname + '.' + self.name
        if dn not in self.records:
            self.records[dn] = []
        return dn

    def get_ptrdomain(self, ip):
        ipaddr = netaddr.IPAddress(ip)
        dn = ipaddr.reverse_dns
        if dn not in self.ptr_records:
            self.ptr_records[dn] = []
        return dn

    def output_records(self, out):
        for name, rrs in self.records.items():
            out('%s => %s' % (name, ', '.join([
                '%s(%s)' % (
                    rdata.__class__.__name__,
                    rdata) for rdata in rrs
            ])))
        for name, rrs in self.ptr_records.items():
            out('%s => %s' % (name, ', '.join([
                '%s(%s)' % (
                    rdata.__class__.__name__,
                    rdata) for rdata in rrs
            ])))

    def isPtrdomain(self, qn):
        return str(qn) in self.ptr_records

    def isSubdomain(self, qn):
        return qn.matchSuffix(self.get_subdomain('@'))

    def inDomain(self, qn):
        return self.isSubdomain(qn) or self.isPtrdomain(qn)

    def search(self, qn, qt):
        """
        qn: query domain name, DNSLabel
        qt: query domain type, default 'A' and 'AAAA'
        """
        r = []
        if qt == 'PTR' and self.isPtrdomain(qn):
            for name, rrs in self.ptr_records.items():
                if qn == name:
                    for rdata in rrs:
                        r.append({
                            'type': 'PTR',
                            'rdata': rdata,
                        })
            if not r:
                rdata = dnslib.PTR(
                    '-'.join(str(qn).split('.')[:-3][::-1]) +
                    '.' +
                    self.get_subdomain('dynamic')
                )
                r.append({
                    'type': 'PTR',
                    'rdata': rdata,
                })
        elif self.isSubdomain(qn):
            for name, rrs in self.records.items():
                if name == qn:
                    for rdata in rrs:
                        rqt = rdata.__class__.__name__
                        if qt in ['*', rqt]:
                            r.append({
                                'type': rqt,
                                'rdata': rdata,
                            })
                            logger.debug('Find: %s => %s(%s)' % (
                                name, rqt, rdata
                            ))
                        elif rqt in ['CNAME']:
                            r.append({
                                'type': rqt,
                                'rdata': rdata,
                            })
                            logger.debug('Find: %s => %s(%s)' % (
                                name, rqt, rdata
                            ))
                            r += self.search(rdata.label, qt)
        return r


class HostDomain(Domain):
    """
    transfer hosts file into special domain
    """
    def create(self, obj):
        """ All are A or AAAA record in hosts file"""
        for line in iter(obj.readline, ''):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            ip, name = line.split()
            dn = self.get_subdomain(name)
            if ':' in ip:
                self.records[dn] += [dnslib.AAAA(ip)]
            else:
                self.records[dn] += [dnslib.A(ip)]

    def get_subdomain(self, subname):
        if subname == '@':
            dn = self.name
        else:
            dn = subname + '.'
        if dn not in self.records:
            self.records[dn] = []
        return dn

    def isSubdomain(self, qn):
        return str(qn) in self.records

    def search(self, qn, qt):
        """
        qn: query domain name, DNSLabel
        qt: query domain type, default 'A' and 'AAAA'
        """
        r = []
        if qt not in ['A', 'AAAA']:
            return r
        for name, rrs in self.records.items():
            if name == qn:
                for rdata in rrs:
                    rqt = rdata.__class__.__name__
                    if qt in ['*', rqt]:
                        r.append({
                            'type': rqt,
                            'rdata': rdata,
                        })
                        logger.debug('Find: %s => %s(%s)' % (
                            name, rqt, rdata
                        ))
        return r
