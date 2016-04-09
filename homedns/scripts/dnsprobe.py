#!/usr/bin/env python
# -*- encoding:utf-8 -*-
# additional packages:
#   pysocks
#   dnslib
#   six
#   lxml
#   BeautifulSoup4

import socket
import logging
import argparse

from six.moves.urllib.parse import urlparse
from bs4 import BeautifulSoup
from dnslib.dns import DNSRecord, DNSQuestion, QTYPE

from webspider.spider import HandlerBase
from webspider.searchengine import getEngine

from ..interface import Interface
from ..server import sendto_upstream


version = '0.1.2'
logger = logging.getLogger(__name__)


class SearchDomain(HandlerBase):
    def __init__(self, engine, domain, max_pages=10, agent=None, proxy=None):
        super(SearchDomain, self).__init__(agent=agent, proxy=proxy)
        self.engine = getEngine(engine)
        self.domain = domain
        self.subdomains = []
        for page in range(max_pages):
            self.engine.set_search(search='site:%s -inurl:www' % domain, page=page)
            self.put(self.engine.get_url(), self.engine.get_data())

    def find_urls(self, soup):
        if self.engine.name == 'baidu':
            return soup.find_all('a', class_='c-showurl')
        elif self.engine.name == 'bing':
            return soup.find_all('cite')
        elif self.engine.name == 'google':
            return soup.find_all('cite')
        return []

    def handle(self, data):
        soup = BeautifulSoup(data, 'lxml')
        for tag in self.find_urls(soup):
            parse = urlparse('//%s' % tag.text, scheme='http')
            if (parse.netloc.endswith(self.domain) and
                    parse.netloc not in self.subdomains):
                print(parse.netloc)
                self.subdomains.append(parse.netloc)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', action='version',
                        version='%%(prog)s %s' % version)
    parser.add_argument('-v', '--verbose', help='verbose help',
                        action='count', default=0)
    parser.add_argument('--user-agent', help='http user agent')
    parser.add_argument('--dns-server', help='use dns server or use default')
    parser.add_argument('--proxy', help='proxy server, socks5://127.0.0.1:1080')
    parser.add_argument(
        '--engine',
        choices=('baidu', 'bing', 'google'),
        default='baidu',
        help='search engine',
    )
    parser.add_argument('--output', help='output text file')
    parser.add_argument('--max-page', type=int, default=10, help='searching pages')
    parser.add_argument('domain', help='search domain')
    args = parser.parse_args()

    logging.basicConfig(level=(logging.WARNING - args.verbose * 10))

    subdomains = set()
    # domain server
    if args.dns_server:
        server_ip = args.dns_server
    else:
        iface = Interface()
        default_dns = iface.get_dnserver() or ['114.114.114.114', '114.114.115.115']
        server_ip = default_dns[0]
    server_port = 53
    # find domain from domain server
    for qtype in ['NS', 'MX', 'A']:
        try:
            q = DNSRecord(q=DNSQuestion(args.domain, getattr(QTYPE, qtype)))
            print('Search %s from %s: ' % (qtype, server_ip))
            a_pkt = sendto_upstream(q.pack(), server_ip, server_port, timeout=5)
            a = DNSRecord.parse(a_pkt)
        except socket.error as err:
            print('\t%s' % err)
            continue
        for r in a.rr:
            rqn = str(r.rdata)
            rqt = QTYPE[r.rtype]
            if rqt in ['NS']:
                rqn = rqn.rstrip('.')
                subdomains.add(rqn)
            elif rqt in ['MX']:
                rqn = rqn.rpartition(' ')[2].rstrip('.')
                subdomains.add(rqn)
            else:
                rqn = rqn.rstrip('.')
                subdomains.add(rqn)
            print('\t%s' % rqn)

    # find domain from searching engine
    search_domain = SearchDomain(
        args.engine, args.domain,
        max_pages=args.max_page,
        agent=args.user_agent,
        proxy=args.proxy,
    )
    search_domain.run_once()
    subdomains |= set(search_domain.subdomains)
    if args.output:
        with open(args.output, 'wb') as f:
            f.write('\n'.join(tuple(subdomains)).encode('ascii'))


if __name__ == '__main__':
    main()
