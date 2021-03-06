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
        logger.warn('Update rules %s', loader)
        self.blacklist = set()
        self.whitelist = set()
        self.create(loader, cache=cache)
        self.updating = False

    def create(self, loader, cache=True):
        self.loader = loader
        try:
            line = None
            loader_io = loader.open(cache=cache)
            for line in iter(loader_io.readline, ''):
                line = line.strip()
                if not line or line[0] in ('!', '['):
                    continue
                # @@ white list
                if line.startswith('@@'):
                    domain_list = self.whitelist
                    line = line.lstrip('@@')
                else:
                    domain_list = self.blacklist
                # remove protocols, http://
                line = line.rpartition('://')[2]
                # remove url, /url, /^
                url = line.partition('/')
                if url[2]:
                    continue
                line = url[0]
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
        except Exception as err:
            logger.error('Load %s error: %s with "%s"' % (self, err, line))
            return

    def _inList(self, domain_list, host):
        level = 0
        for domain in domain_list:
            if domain == '.*':
                # www.example.com == .*
                level = 1
            elif host[-len(domain):] == domain:
                # www.example.com == .example.com
                #    ^^^^^^^^^^^^
                level = len(domain)
            elif '.' + host == domain:
                # sub.example.com == .sub.example.com
                # full match
                level = 100
        return level

    def isBlock(self, host):
        return self.isBlack(host) > self.isWhite(host)

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
