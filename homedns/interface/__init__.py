import sys

if sys.platform == 'win32':
    try:
        from .win32 import Interface
    except:
        print('Don\'t find WIN32 interface. Use default...')
        from .interface import InterfaceBase as Interface
else:
    from .interface import InterfaceBase as Interface


__all__ = ['Interface']
