#!/usr/bin/env python
# -*- encoding:utf-8 -*-


from ..interface import InterfaceBase
from .adapter import AdapterInfo


class Interface(InterfaceBase):
    def __init__(self):
        super(Interface, self).__init__()
        adapter_info = AdapterInfo()
        min_metric = 1000
        for adapter in adapter_info.get():
            iface = {}
            iface['desc'] = adapter.description
            iface['macaddr'] = adapter.physicalAddr
            iface['status'] = adapter.status
            iface['dhcp'] = adapter.dhcpEnabled
            iface['ipaddr'] = [addr for addr in adapter.addrUnicast]
            iface['dhcpserver'] = [addr for addr in adapter.addrDhcp]
            iface['gateway'] = [addr for addr in adapter.addrGateway]
            if (iface['status'] and
                    iface['gateway'] and iface['ipaddr'] and
                    adapter.ipv4Metric < min_metric):
                min_metric = adapter.ipv4Metric
                self.gateway_iface = adapter.name
            self.interfaces[adapter.name] = iface
