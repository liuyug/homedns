#!/usr/bin/env python
# -*- encoding:utf-8 -*-

# generate domain list from adblock rules.


class Adblock(object):
    def __init__(self, fobj):
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
            if domain == '*' or host[-len(domain):] == domain:
                return True
        return False

    def isBlock(self, host):
        return not self.isWhite(host) and self.isBlack(host)

    def isWhite(self, host):
        return self._inList(self.whitelist, host)

    def isBlack(self, host):
        return self._inList(self.blacklist, host)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--rules', help='adblock rules file')
    parser.add_argument('--host', help='search host')
    args = parser.parse_args()

    ab = Adblock(open(args.rules))
    print(ab.inList(args.host))
