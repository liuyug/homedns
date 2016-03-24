#!/usr/bin/env python
# -*- encoding:utf-8 -*-

import netifaces


def getifaces():
    return netifaces.interfaces()


def getifaddrs(iface):
    addr = {}
    for k, v in netifaces.ifaddresses(iface).items():
        addr[netifaces.address_families[k]] = v
    return addr


def getdefaultiface():
    gw = netifaces.gateways()
    for v in gw.get('default').values():
        return v[1]
