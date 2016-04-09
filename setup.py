
import sys

from setuptools import setup, Extension
# from distutils.core import setup, Extension

from homedns.globalvars import version


ext_modules = []
packages = []

if sys.platform == 'win32':
    ext_modules.append(Extension(
        '_adapter',
        sources=[
            'homedns/interface/win32/adapter.i',
            'homedns/interface/win32/adapter.cpp'
        ],
        libraries=['ws2_32', 'iphlpapi'],
        swig_opts=['-Wall', '-c++'],
    ))
    packages.append('homedns.interface.win32.adapter')


setup(
    name='HomeDNS',
    version=version,
    description='This is a tiny DNS server only for family used.',
    ext_modules=ext_modules,
    packages=packages,
)
