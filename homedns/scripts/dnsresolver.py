#!/usr/bin/env python
# -*- encoding:utf-8 -*-

import sys
import socket
import argparse


version = '0.1.0'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', action='version',
                        version='%%(prog)s %s' % version)
    parser.add_argument('domain', nargs='*', help='search domain')
    args = parser.parse_args()

    domains = []
    if args.domain:
        domains = args.domain
    else:
        domains = sys.stdin.readlines()
    while domains:
        domain = domains.pop().strip()
        if domain and not domain.startswith('#'):
            try:
                host_ip = socket.gethostbyname(domain)
                print('%s\t\t%s' % (host_ip, domain))
            except socket.error:
                domains.insert(0, domain)


if __name__ == '__main__':
    main()
