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
from dnslib.dns import DNSRecord, DNSQuestion, QTYPE, DNSError

from webspider.searchengine import getEngine

from ..interface import Interface
from ..server import sendto_upstream


version = '0.1.4'
logger = logging.getLogger(__name__)


def main():
    epilog = "%(prog)s --engine baidu zonetransfer.me"
    parser = argparse.ArgumentParser(epilog=epilog)
    parser.add_argument('--version', action='version',
                        version='%%(prog)s %s' % version)
    parser.add_argument('-v', '--verbose', help='verbose help',
                        action='count', default=0)
    parser.add_argument('--output', help='output text file')

    dns_group = parser.add_argument_group('Find subdomains from DNS service')
    dns_group.add_argument('--dns-server', help='DNS server or use system DNS server')
    dns_group.add_argument('--tcp', action='store_true', help='use TCP mode')
    dns_group.add_argument('--timeout', default=5, help='connection timeout. default is 5')

    search_group = parser.add_argument_group('Find subdomains from searching engine')
    search_group.add_argument(
        '--engine',
        choices=('baidu', 'bing', 'google'),
        help='search engine',
    )
    search_group.add_argument('--user-agent', help='http user agent')
    search_group.add_argument('--record-max', type=int, default=100, help='searching max record number')
    search_group.add_argument('--proxy', help='proxy server, socks5://127.0.0.1:1080')

    parser.add_argument('domain', help='search domain')
    args = parser.parse_args()

    logging.basicConfig(format='%(message)s', level=(logging.WARNING - args.verbose * 10))

    subdomains = set()
    # domain server
    logger.warn('#' * 80)
    if args.dns_server:
        server_ip = args.dns_server
    else:
        iface = Interface()
        default_dns = iface.get_dnserver() or ['114.114.114.114', '114.114.115.115']
        server_ip = default_dns[0]
    server_port = 53
    logger.warn('# DNS server: %s' % server_ip)

    try:
        qtype = 'SOA'
        q = DNSRecord(q=DNSQuestion(args.domain, getattr(QTYPE, qtype)))
        a_pkt = sendto_upstream(
            q.pack(), server_ip, server_port,
            timeout=args.timeout
        )
        a = DNSRecord.parse(a_pkt)
        if a.rr:
            rqn = str(a.rr[0].rdata.mname).rstrip('.')
            server_ip = socket.gethostbyname(rqn)
            logger.warn('# Find primary DNS server: %s(%s)' % (rqn, server_ip))
        else:
            logger.warn('# Failed to find NS record. Use default DNS server: %s.' % server_ip)
    except socket.error as err:
        logger.error('Failed to find the dns server of %s: %s' % (args.domain, err))
    # find domain from domain server
    for qtype in ['AXFR', 'TXT', 'NS', 'MX', 'A', 'AAAA', 'CNAME']:
        try:
            q = DNSRecord(q=DNSQuestion(args.domain, getattr(QTYPE, qtype)))
            logger.warn('# Search record %s from %s: ' % (qtype, server_ip))
            a_pkt = sendto_upstream(
                q.pack(), server_ip, server_port,
                timeout=args.timeout,
                tcp=args.tcp or qtype == 'AXFR',
            )
            a = DNSRecord.parse(a_pkt)
        except socket.error as err:
            logger.error('# \t%s' % err)
            continue
        except DNSError as err:
            logger.error('# \t%s' % err)
            continue
        for r in a.rr:
            rqt = QTYPE.get(r.rtype, r.rtype)
            if rqt in ['A', 'AAAA']:
                rqn = str(r.rdata).rstrip('.')
                subdomains.add(rqn)
            elif rqt in ['NS', 'MX', 'CNAME']:
                rqn = str(r.rdata.label).rstrip('.')
                subdomains.add(rqn)
            elif rqt in ['PTR', 'SOA', 'TXT']:
                rqn = str(r.rdata)
                logger.error('#   Ignore record %s: %s' % (rqt, rqn))
                continue
            else:
                logger.error('#   Ignore record %s' % rqt)
                continue
            logger.warn('%s' % (rqn))
        if qtype == 'AXFR' and a.rr:
            logger.warn('# Find record AXFR(Zone Transfered Records)!!! IGNORE other...')
            break

    # find domain from searching engine
    if args.engine:
        logger.warn('#' * 80)
        engine = getEngine(args.engine, agent=args.user_agent, proxy=args.proxy)
        engine.addSearch(text=['site:%s' % args.domain, '-inurl:www'])
        engine.addSearch(record_max=args.record_max)
        logger.warn('# Search subdomains of %s from %s' % (args.domain, args.engine))
        engine.run_once()
        for m in engine.matchs:
            parse = urlparse(m['url'])
            if (parse.netloc.endswith(args.domain) and
                    parse.netloc not in subdomains):
                subdomains.add(parse.netloc)
                logger.warn('%s' % (parse.netloc))
    if args.output:
        output_file = args.output
    else:
        output_file = args.domain + '.txt'
    with open(output_file, 'w') as f:
        for d in subdomains:
            f.write('%s\n' % d)
    logger.warn('# Output all results to %s' % output_file)


if __name__ == '__main__':
    main()
