#!/usr/bin/env python
# -*- encoding:utf-8 -*-


class InterfaceBase(object):
    def __init__(self):
        self.interfaces = {}
        self.gateway_iface = ''

    def isIPv4(self, ip):
        if not ip:
            return False
        if ':' in ip:
            return False
        return True

    def includeIPv4(self, ips):
        for ip in ips:
            if self.isIPv4(ip):
                return True
        return False

    def get_gateway(self):
        iface = self.interfaces.get(self.gateway_iface)
        if iface:
            return iface.get('gateway')

    def get_dnserver(self):
        iface = self.interfaces.get(self.gateway_iface)
        if iface:
            return iface.get('dnserver')

    def get_dhcpserver(self):
        iface = self.interfaces.get(self.gateway_iface)
        if iface:
            return iface.get('dhcpserver')
