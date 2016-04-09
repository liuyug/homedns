import sys

from ..interface import Interface


def test():
    iface = Interface()
    if sys.platform != 'win32':
        print('Please run it under Win32 platform')
        return
    print('gateway: %s' % iface.gateway_iface)
    print('interfaces:')
    for k, v in iface.interfaces.items():
        print(k)
        print(v)


if __name__ == '__main__':
    test()
