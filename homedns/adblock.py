#!/usr/bin/env python
# -*- encoding:utf-8 -*-

# generate domain list from adblock rules.

import threading
import logging


logger = logging.getLogger(__name__)


class Adblock(object):
    def __init__(self, name):
        self.name = name
        self.loader = None
        self.updating = False
        self.blacklist = set()
        self.whitelist = set()

    def __repr__(self):
        return '<Adblock: %s>' % self.name

    def __bool__(self):
        return bool(self.blacklist)

    def isNeedUpdate(self, refresh):
        if self.updating or refresh == 0:
            return False
        if not self.blacklist:
            return True
        return self.loader.isNeedUpdate(refresh)

    def async_update(self, loader=None):
        # XXX: resource Lock?
        t = threading.Thread(
            target=self.update,
            kwargs={
                'loader': loader,
                'cache': False,
            }
        )
        t.start()

    def update(self, loader=None, cache=True):
        if not loader:
            loader = self.loader
        self.updating = True
        logger.error('Update rules %s', loader)
        self.blacklist = set()
        self.whitelist = set()
        self.create(loader, cache=cache)
        self.updating = False

    def create(self, loader, cache=True):
        self.loader = loader
        try:
            loader_io = loader.open(cache=cache)
        except Exception as err:
            logger.error('Load %s error: %s' % (self, err))
            return
        for line in iter(loader_io.readline, ''):
            line = line.strip()
            if not line or line[0] in ('!', '['):
                continue
            if line.startswith('@@'):
                domain_list = self.whitelist
                line = line.lstrip('@@')
            else:
                domain_list = self.blacklist
            # remove protocols, http://
            line = line.rpartition('://')[2]
            # remove url, /url, /^
            line = line.partition('/')[0]
            # drop IP address, 1.1.1.1
            if line.rpartition('.')[2].isdigit():
                continue
            # non-domain
            if '.' not in line:
                continue
            # remove *
            lp = line.partition('*')
            line = lp[0] if '.' in lp[0] else lp[2]
            # remove ||
            for ch in ('||'):
                line = line.lstrip(ch)
            # add '.' to match every item in domain
            if line[0] != '.':
                line = '.' + line
            # only add lower character
            domain_list.add(line.lower())

    def _inList(self, domain_list, host):
        for domain in domain_list:
            if domain == '.*' or host[-len(domain):] == domain:
                return True
        return False

    def isBlock(self, host):
        return not self.isWhite(host) and self.isBlack(host)

    def isWhite(self, host):
        return self._inList(self.whitelist, host)

    def isBlack(self, host):
        return self._inList(self.blacklist, host)

    def output_list(self):
        line = []
        line.append('White: %s' % self.whitelist)
        line.append('Black: %s' % self.blacklist)
        return line

if __name__ == '__main__':
    import argparse
    import os.path
    parser = argparse.ArgumentParser()
    parser.add_argument('--rules', help='adblock rules file')
    parser.add_argument('--host', help='search host')
    args = parser.parse_args()

    from . import globalvars
    from .loader import TxtLoader
    globalvars.init()
    globalvars.config_dir = ''
    ab = Adblock(os.path.basename(args.rules))
    ab.create(TxtLoader(args.rules))
    print('Black list: %s' % ab.isBlack(args.host))
    print('White list: %s' % ab.isWhite(args.host))
