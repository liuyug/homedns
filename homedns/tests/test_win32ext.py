#!/usr/bin/env python
# -*- encoding:utf-8 -*-


from ..interface.win32.adapter import AdapterInfo


def main():
    ni = AdapterInfo()
    print('Hostname: %s' % ni.hostname)

    print('Interface:')
    for iface in ni.get():
        print('    %s' % iface.name)
        print('        Description: %s' % iface.description)
        print('        Physical Address: %s' % iface.physicalAddr)
        print('        Status: %s' % iface.status)
        print('        Tx Speed: %s Mbps' % iface.txSpeed)
        print('        Rx Speed: %s Mbps' % iface.rxSpeed)
        print('        MTU: %s' % iface.mtu)
        print('        IPv4 Enabled: %s' % iface.ipv4Enabled)
        print('        IPv6 Enabled: %s' % iface.ipv6Enabled)
        print('        DHCP Enabled: %s' % iface.dhcpEnabled)
        print('        DHCP Server: %s' % [addr for addr in iface.addrDhcp])
        print('        DnsServer: %s' % [addr for addr in iface.addrDnsServer])
        print('        Dns Suffix: %s' % iface.dnsSuffix)
        print('        Unicast: %s' % [addr for addr in iface.addrUnicast])
        print('        Anycast: %s' % [addr for addr in iface.addrAnycast])
        print('        Multicast: %s' % [addr for addr in iface.addrMulticast])
        print('        Gateway: %s' % [addr for addr in iface.addrGateway])
        print('        IPv4 Metric: %s' % iface.ipv4Metric)
        print('        IPv6 Metric: %s' % iface.ipv6Metric)

if __name__ == '__main__':
    main()
