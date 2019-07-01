# dns cache

import os
import time


class Cache(object):
    _timeout = 60 * 30  # seconds


class FileCache(Cache):
    pass


class MemoryCache(Cache):
    _mobj = {}

    @classmethod
    def add(cls, key, value):
        cls._mobj[key] = {
            'value': value,
            'time': time.time(),
        }

    @classmethod
    def delete(cls, key):
        del cls._mobj[key]

    @classmethod
    def clear(cls):
        cls._mobj = {}

    @classmethod
    def get(cls, key):
        data = cls._mobj.get(key)
        if data:
            if (time.time() - data['time']) > cls._timeout:
                cls.delete(key)
            else:
                return data['value']


class DNSCache(MemoryCache):
    pass
