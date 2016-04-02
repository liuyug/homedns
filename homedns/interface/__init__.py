import sys

if sys.platform == 'win32':
    from .win32.interface import Interface
else:
    from .interface import InterfaceBase as Interface


__all__ = ['Interface']
