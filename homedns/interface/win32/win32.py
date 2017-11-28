import ctypes
import struct
import ipaddress
import ctypes.wintypes
from ctypes.wintypes import DWORD, BYTE
from socket import AF_INET


# Windows define
MAX_ADAPTER_ADDRESS_LENGTH = 8
MAX_DHCPV6_DUID_LENGTH = 130

ERROR_BUFFER_OVERFLOW = 0x6f
NO_ERROR = 0x0


# flags
class Flags():
    IP_ADAPTER_DDNS_ENABLED = 0x0001  # Dynamic DNS is enabled on this adapter.
    IP_ADAPTER_REGISTER_ADAPTER_SUFFIX = 0x0002  # Register the DNS suffix for this adapter.
    IP_ADAPTER_DHCP_ENABLED = 0x0004  # The Dynamic Host Configuration Protocol (DHCP) is enabled on this adapter.
    IP_ADAPTER_RECEIVE_ONLY = 0x0008  # The adapter is a receive-only adapter.
    IP_ADAPTER_NO_MULTICAST = 0x0010  # The adapter is not a multicast recipient.
    IP_ADAPTER_IPV6_OTHER_STATEFUL_CONFIG = 0x0020  # The adapter contains other IPv6-specific stateful configuration information.
    IP_ADAPTER_NETBIOS_OVER_TCPIP_ENABLED = 0x0040  # The adapter is enabled for NetBIOS over TCP/IP.
    IP_ADAPTER_IPV4_ENABLED = 0x0080  # The adapter is enabled for IPv4.
    IP_ADAPTER_IPV6_ENABLED = 0x0100  # The adapter is enabled for IPv6.
    IP_ADAPTER_IPV6_MANAGE_ADDRESS_CONFIG = 0x0200

    def dhcp_enable(cls, flags):
        return bool(flags & cls.IP_ADAPTER_DHCP_ENABLED)

    def ipv4_enable(cls, flags):
        return bool(flags & cls.IP_ADAPTER_DHCP_ENABLED)


class IfType():
    IF_TYPE_OTHER = 1  # Some other type of network interface.
    IF_TYPE_ETHERNET_CSMACD = 6  # An Ethernet network interface.
    IF_TYPE_ISO88025_TOKENRING = 9  # A token ring network interface.
    IF_TYPE_PPP = 23  # A PPP network interface.
    IF_TYPE_SOFTWARE_LOOPBACK = 24  # A software loopback network interface.
    IF_TYPE_ATM = 37  # An ATM network interface.
    IF_TYPE_IEEE80211 = 71  # An IEEE 802.11 wireless network interface.
    IF_TYPE_TUNNEL = 131  # A tunnel type encapsulation network interface.
    IF_TYPE_IEEE1394 = 144


class OperStatus():
    IfOperStatusUp = 1
    IfOperStatusDown = 2
    IfOperStatusTesting = 3
    IfOperStatusUnknown = 4
    IfOperStatusDormant = 5
    IfOperStatusNotPresent = 6
    IfOperStatusLowerLayerDown = 7

    def up(cls, oper_status):
        return oper_status == cls.IfOperStatusUp

    def down(cls, oper_status):
        return oper_status == cls.IfOperStatusDown

    def desc(cls, oper_status):
        if oper_status == cls.IfOperStatusUp:
            return 'up'
        elif oper_status == cls.IfOperStatusDown:
            return 'down'
        elif oper_status == cls.IfOperStatusTesting:
            return 'testing'
        elif oper_status == cls.IfOperStatusUnknown:
            return 'unknown'
        elif oper_status == cls.IfOperStatusDormant:
            return 'dormant'
        elif oper_status == cls.IfOperStatusNotPresent:
            return 'not present'
        elif oper_status == cls.IfOperStatusLowerLayerDown:
            return 'lower layer down'
        else:
            return 'other: %s' % oper_status


class SOCKADDR(ctypes.Structure):
    _fields_ = [
        ('family', ctypes.c_ushort),
        ('data', ctypes.c_byte * 14),
    ]


LPSOCKADDR = ctypes.POINTER(SOCKADDR)


class SOCKET_ADDRESS(ctypes.Structure):
    _fields_ = [
        ('address', LPSOCKADDR),
        ('length', ctypes.c_int),
    ]


class _IP_ADAPTER_ADDRESSES_METRIC(ctypes.Structure):
    _fields_ = [
        ('length', ctypes.c_ulong),
        ('interface_index', DWORD),
    ]


class _IP_ADAPTER_ADDRESSES_U1(ctypes.Union):
    _fields_ = [
        ('alignment', ctypes.c_ulonglong),
        ('metric', _IP_ADAPTER_ADDRESSES_METRIC),
    ]


class IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
    pass


PIP_ADAPTER_UNICAST_ADDRESS = ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)
IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
    ("length", ctypes.c_ulong),
    ("flags", ctypes.wintypes.DWORD),
    ("next", PIP_ADAPTER_UNICAST_ADDRESS),
    ("address", SOCKET_ADDRESS),
    ("prefix_origin", ctypes.c_int),
    ("suffix_origin", ctypes.c_int),
    ("dad_state", ctypes.c_int),
    ("valid_lifetime", ctypes.c_ulong),
    ("preferred_lifetime", ctypes.c_ulong),
    ("lease_lifetime", ctypes.c_ulong),
    ("on_link_prefix_length", ctypes.c_ubyte)
]


# it crashes when retrieving prefix data :(
class IP_ADAPTER_PREFIX(ctypes.Structure):
    pass


PIP_ADAPTER_PREFIX = ctypes.POINTER(IP_ADAPTER_PREFIX)
IP_ADAPTER_PREFIX._fields_ = [
    ("alignment", ctypes.c_ulonglong),
    ("next", PIP_ADAPTER_PREFIX),
    ("address", SOCKET_ADDRESS),
    ("prefix_length", ctypes.c_ulong)
]


class IP_ADAPTER_ADDRESSES(ctypes.Structure):
    pass


LP_IP_ADAPTER_ADDRESSES = ctypes.POINTER(IP_ADAPTER_ADDRESSES)


class IP_ADAPTER_GATEWAY_ADDRESS(ctypes.Structure):
    pass


PIP_ADAPTER_GATEWAY_ADDRESS_LH = ctypes.POINTER(IP_ADAPTER_GATEWAY_ADDRESS)
IP_ADAPTER_GATEWAY_ADDRESS._fields_ = [
    ('length', ctypes.c_ulong),
    ('reserved', DWORD),
    ('next', PIP_ADAPTER_GATEWAY_ADDRESS_LH),
    ('address', SOCKET_ADDRESS)
]


class IP_ADAPTER_DNS_SERVER_ADDRESS(ctypes.Structure):
    pass


PIP_ADAPTER_DNS_SERVER_ADDRESS = ctypes.POINTER(IP_ADAPTER_DNS_SERVER_ADDRESS)
IP_ADAPTER_DNS_SERVER_ADDRESS._fields_ = [
    ('length', ctypes.c_ulong),
    ('reserved', DWORD),
    ('next', PIP_ADAPTER_DNS_SERVER_ADDRESS),
    ('address', SOCKET_ADDRESS)
]


# for now, just use void * for pointers to unused structures
PIP_ADAPTER_ANYCAST_ADDRESS = ctypes.c_void_p
PIP_ADAPTER_MULTICAST_ADDRESS = ctypes.c_void_p
PIP_ADAPTER_WINS_SERVER_ADDRESS_LH = ctypes.c_void_p
PIP_ADAPTER_DNS_SUFFIX = ctypes.c_void_p

IF_OPER_STATUS = ctypes.c_uint  # this is an enum, consider http://code.activestate.com/recipes/576415/
IF_LUID = ctypes.c_uint64

NET_IF_COMPARTMENT_ID = ctypes.c_uint32
GUID = ctypes.c_byte * 16
NET_IF_NETWORK_GUID = GUID
NET_IF_CONNECTION_TYPE = ctypes.c_uint  # enum
TUNNEL_TYPE = ctypes.c_uint  # enum

IP_ADAPTER_ADDRESSES._fields_ = [
    ('length', ctypes.c_ulong),
    ('interface_index', DWORD),
    ('next', LP_IP_ADAPTER_ADDRESSES),
    ('adapter_name', ctypes.c_char_p),
    ('first_unicast_address', PIP_ADAPTER_UNICAST_ADDRESS),
    ('first_anycast_address', PIP_ADAPTER_ANYCAST_ADDRESS),
    ('first_multicast_address', PIP_ADAPTER_MULTICAST_ADDRESS),
    ('first_dns_server_address', PIP_ADAPTER_DNS_SERVER_ADDRESS),
    ('dns_suffix', ctypes.c_wchar_p),
    ('description', ctypes.c_wchar_p),
    ('friendly_name', ctypes.c_wchar_p),
    ('physical_address', BYTE * MAX_ADAPTER_ADDRESS_LENGTH),
    ('physical_address_length', DWORD),
    ('flags', DWORD),
    ('mtu', DWORD),
    ('interface_type', DWORD),
    ('oper_status', IF_OPER_STATUS),
    ('ipv6_interface_index', DWORD),
    ('zone_indices', DWORD * 16),
    ('first_prefix', PIP_ADAPTER_PREFIX),
    ('transmit_link_speed', ctypes.c_uint64),
    ('receive_link_speed', ctypes.c_uint64),
    ('first_wins_server_address', PIP_ADAPTER_WINS_SERVER_ADDRESS_LH),
    ('first_gateway_address', PIP_ADAPTER_GATEWAY_ADDRESS_LH),
    ('ipv4_metric', ctypes.c_ulong),
    ('ipv6_metric', ctypes.c_ulong),
    ('luid', IF_LUID),
    ('dhcpv4_server', SOCKET_ADDRESS),
    ('compartment_id', NET_IF_COMPARTMENT_ID),
    ('network_guid', NET_IF_NETWORK_GUID),
    ('connection_type', NET_IF_CONNECTION_TYPE),
    ('tunnel_type', TUNNEL_TYPE),
    ('dhcpv6_server', SOCKET_ADDRESS),
    ('dhcpv6_client_duid', ctypes.c_byte * MAX_DHCPV6_DUID_LENGTH),
    ('dhcpv6_client_duid_length', ctypes.c_ulong),
    ('dhcpv6_iaid', ctypes.c_ulong),
    ('first_dns_suffix', PIP_ADAPTER_DNS_SUFFIX),
]


def to_ipv4address(socket_address):
    """ translate SOCKET_ADDRESS to Python ipaddress """
    if not socket_address.address:
        return ''
    ad = socket_address.address.contents
    ip_int = struct.unpack('>2xI8x', ad.data)[0]
    return ipaddress.IPv4Address(ip_int)


def GetAdaptersAddresses():
    size = ctypes.c_ulong()
    GetAdaptersAddresses = ctypes.windll.iphlpapi.GetAdaptersAddresses
    GetAdaptersAddresses.argtypes = [
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.POINTER(IP_ADAPTER_ADDRESSES),
        ctypes.POINTER(ctypes.c_ulong),
    ]
    GetAdaptersAddresses.restype = ctypes.c_ulong

    # GAA_FLAG_SKIP_UNICAST = 0x0001  # Do not return unicast addresses.
    # GAA_FLAG_SKIP_ANYCAST = 0x0002  # Do not return IPv6 anycast addresses.
    # GAA_FLAG_SKIP_MULTICAST = 0x0004  # Do not return multicast addresses.
    # GAA_FLAG_SKIP_DNS_SERVER = 0x0008  # Do not return addresses of DNS servers.
    # GAA_FLAG_INCLUDE_PREFIX = 0x0010  # Return a list of IP address prefixes on this adapter. When this flag is set, IP address prefixes are returned for both IPv6 and IPv4 addresses.
    # GAA_FLAG_SKIP_FRIENDLY_NAME = 0x0020  # Do not return the adapter friendly name.
    # GAA_FLAG_INCLUDE_WINS_INFO = 0x0040  # Return addresses of Windows Internet Name Service (WINS) servers.
    GAA_FLAG_INCLUDE_GATEWAYS = 0x0080  # Return the addresses of default gateways.
    # GAA_FLAG_INCLUDE_ALL_INTERFACES = 0x0100  # Return addresses for all NDIS interfaces.
    # GAA_FLAG_INCLUDE_ALL_COMPARTMENTS = 0x0200  # Return addresses in all routing compartments.  This flag is not currently supported and reserved for future use.
    # GAA_FLAG_INCLUDE_TUNNEL_BINDINGORDER = 0x0400
    flags = GAA_FLAG_INCLUDE_GATEWAYS
    res = GetAdaptersAddresses(AF_INET, flags, None, None, size)
    if res != ERROR_BUFFER_OVERFLOW:
        raise RuntimeError("Error getting structure length (%d)" % res)
    pointer_type = ctypes.POINTER(IP_ADAPTER_ADDRESSES)
    size.value = 15000
    buffer = ctypes.create_string_buffer(size.value)
    struct_p = ctypes.cast(buffer, pointer_type)
    res = GetAdaptersAddresses(AF_INET, flags, None, struct_p, size)
    if res != NO_ERROR:
        raise RuntimeError("Error retrieving table (%d)" % res)
    while struct_p:
        yield struct_p.contents
        struct_p = struct_p.contents.next


def get_ifaddrs():
    result = {}
    for i in GetAdaptersAddresses():

        fu = i.first_unicast_address.contents
        ip = to_ipv4address(fu.address)
        ip_if = ipaddress.IPv4Interface("{0}/{1}".format(ip, fu.on_link_prefix_length))

        d = {}
        d['description'] = i.description
        d['address'] = "{0}".format(ip)
        d['netmask'] = "{0}".format(ip_if.netmask)
        d['broadcast'] = "{0}".format(ip_if.network.broadcast_address)
        d['network'] = "{0}".format(ip_if.network.network_address)

        dhcp_server = []
        dhcp = to_ipv4address(i.dhcpv4_server)
        if dhcp:
            dhcp_server.append(str(dhcp))
        d['dhcp_server'] = dhcp_server
        d['dhcp_enable'] = Flags().dhcp_enable(i.flags)
        d['dns_suffix'] = i.dns_suffix
        d['oper_status'] = OperStatus().desc(i.oper_status)

        gateways = []
        gw = i.first_gateway_address
        while gw:
            gateways.append(str(to_ipv4address(gw.contents.address)))
            gw = gw.contents.next
        d['gateway'] = gateways

        d['ipv4_metric'] = i.ipv4_metric

        dns_server = []
        dns = i.first_dns_server_address
        while dns:
            dns_server.append(str(to_ipv4address(dns.contents.address)))
            dns = dns.contents.next
        d['dns_server'] = dns_server

        mac_address = []
        for x in range(i.physical_address_length):
            mac_address.append('%02X' % (i.physical_address[x] & 0xff))
        d['mac_address'] = ':'.join(mac_address)
        result[i.description] = d
    return result


if __name__ == "__main__":
    d = get_ifaddrs()
    for iface in d.values():
        print('-' * 80)
        print('description: %(description)s' % iface)
        print('address: %(address)s' % iface)
        print('netmask: %(netmask)s' % iface)
        print('broadcast: %(broadcast)s' % iface)
        print('network: %(network)s' % iface)
        print('dhcp_enable: %(dhcp_enable)s' % iface)
        print('dhcp_server: %(dhcp_server)s' % iface)
        print('dns_server: %(dns_server)s' % iface)
        print('dns_suffix: %(dns_suffix)s' % iface)
        print('oper_status: %(oper_status)s' % iface)
        print('gateway: %(gateway)s' % iface)
        print('ipv4_metric: %(ipv4_metric)s' % iface)
        print('mac_address: %(mac_address)s' % iface)
