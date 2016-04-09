#!/usr/bin/env python
# -*- encoding:utf-8 -*-


class InterfaceBase(object):
    def __init__(self):
        self.interfaces = {}
        self.gateway_iface = ''

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
