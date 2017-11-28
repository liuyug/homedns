#!/usr/bin/env python
# -*- encoding:utf-8 -*-


from ..interface import InterfaceBase
from .win32 import get_ifaddrs


class Interface(InterfaceBase):
    def __init__(self):
        super(Interface, self).__init__()
        ifaddrs = get_ifaddrs()
        min_metric = 1000
        for ifaddr in ifaddrs.values():
            iface = {}
            iface['desc'] = ifaddr['description']
            iface['macaddr'] = ifaddr['mac_address']
            iface['status'] = ifaddr['oper_status']
            iface['dhcp'] = ifaddr['dhcp_enable']
            iface['ipaddr'] = [ifaddr['address']]
            iface['dhcpserver'] = ifaddr['dhcp_server']
            iface['gateway'] = ifaddr['gateway']
            iface['dnserver'] = ifaddr['dns_server']
            # ipv4 gateway
            if (iface['status'] and
                    self.includeIPv4(iface['gateway']) and
                    self.includeIPv4(iface['ipaddr']) and
                    ifaddr['ipv4_metric'] < min_metric):
                min_metric = ifaddr['ipv4_metric']
                self.gateway_iface = iface['desc']
            self.interfaces[iface['desc']] = iface
