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
    parser.add_argument('--timeout', default=5, help='socket timeout')
    parser.add_argument('domain', nargs='*', help='search domain')
    args = parser.parse_args()

    domains = []
    if args.domain:
        domains = args.domain
    else:
        domains = sys.stdin.readlines()
    socket.setdefaulttimeout(float(args.timeout))
    err_domains = []
    while domains or err_domains:
        if domains:
            domain = domains.pop().strip()
            count = 0
        elif err_domains:
            domain, count = err_domains.pop()
        if domain and not domain.startswith('#'):
            try:
                host_ip = socket.gethostbyname(domain)
                print('%s\t\t%s' % (host_ip, domain))
            except socket.error:
                if count < 3:
                    err_domains.append((domain, count + 1))
                else:
                    print('# Failed to get host %s' % domain)


if __name__ == '__main__':
    main()
