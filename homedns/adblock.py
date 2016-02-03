#!/usr/bin/env python
# -*- encoding:utf-8 -*-

# generate domain list from adblock rules.


class AdblockType(dict):
    def get_desc(self, vv):
        for k, v in self.items():
            if v == vv:
                return k.upper()


ABTYPE = AdblockType({
    'white': 1,
    'black': -1,
    'unknown': 0,
})


class Adblock(object):
    def __init__(self, obj):
        if isinstance(obj, str):
            fobj = open(obj)
        else:
            fobj = obj
        self.blacklist = set()
        self.whitelist = set()
        for line in iter(fobj.readline, ''):
            line = line.strip()
            if not line or line.startswith(('!', '[')):
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
            # remove || .
            for ch in ('||', '.'):
                line = line.lstrip(ch)
            # only add lower character
            domain_list.add(line.lower())

    def _inList(self, domain_list, host):
        for domain in domain_list:
            if host[-len(domain):] == domain:
                return True
        return False

    def inList(self, host):
        if self._inList(self.whitelist, host):
            return ABTYPE['white']
        elif self._inList(self.blacklist, host):
            return ABTYPE['black']
        return ABTYPE['unknown']

    def isWhite(self, host):
        return self.inList(host) == ABTYPE['white']

    def isBlack(self, host):
        return self.inList(host) == ABTYPE['black']


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--rules', help='adblock rules file')
    parser.add_argument('--host', help='search host')
    args = parser.parse_args()

    ab = Adblock(open(args.rules))
    print(ab.inList(args.host))
