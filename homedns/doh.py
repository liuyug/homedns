
import logging
import json
import re

import urllib.request

import socks
from sockshandler import SocksiPyHandler

import dnslib
from dnslib import RR, QTYPE, DNSRecord

from . import globalvars

logger = logging.getLogger(__name__)


def dict2RR(r):
    re_quote = re.compile(r'\"')
    if QTYPE.SOA == r['type']:
        d = r['data'].split()
        rdata = getattr(dnslib, QTYPE[r['type']])(
            mname=d[0],
            rname=d[1],
            times=[int(dd) for dd in d[2:]],
        )
    elif QTYPE.TXT == r['type']:
        rdata = getattr(dnslib, QTYPE[r['type']])(
            [re_quote.sub('', t) for t in r['data'].split()]
        )
    elif QTYPE.MX == r['type']:
        d = r['data'].split()
        rdata = getattr(dnslib, QTYPE[r['type']])(
            d[0], int(d[1]),
        )
    elif QTYPE.SRV == r['type']:
        d = r['data'].split()
        rdata = getattr(dnslib, QTYPE[r['type']])(
            int(d[0]), int(d[1]), int(d[2]), d[3],
        )
    elif QTYPE.NAPTR == r['type']:
        d = r['data'].split()
        rdata = getattr(dnslib, QTYPE[r['type']])(
            int(d[0]), int(d[1]), d[2], d[3], d[4], d[5],
        )
    elif QTYPE.DNSKEY == r['type']:
        d = r['data'].split()
        rdata = getattr(dnslib, QTYPE[r['type']])(
            int(d[0]), int(d[1]), int(d[2]), d[3],
        )
    elif QTYPE.RRSIG == r['type']:
        d = r['data'].split()
        rdata = getattr(dnslib, QTYPE[r['type']])(
            d[0], int(d[1]), int(d[2]), int(d[3]),
            d[4], d[5], int(d[6]), d[7], d[8],
        )
    elif QTYPE.NSEC == r['type']:
        rdata = getattr(dnslib, QTYPE[r['type']])(
            r['data'].split()
        )
    elif QTYPE.CAA == r['type']:
        d = r['data'].split()
        rdata = getattr(dnslib, QTYPE[r['type']])(
            int(d[0]), d[1], d[2],
        )
    else:
        rdata = getattr(dnslib, QTYPE[r['type']])(
            r['data']
        )
    answer = RR(
        rname=r['name'],
        rtype=r['type'],
        rclass=1, ttl=r['TTL'],
        rdata=rdata,
    )
    return answer


def lookup_upstream(request, reply, server, proxy):
    """
    json-format: https://developers.cloudflare.com/1.1.1.1/dns-over-https/json-format/
    """
    try:
        message = '\tForward to server %(ip)s(%(priority)s)' % server
        message += ' with %s protocol' % server['protocol']
        if server['proxy'] and proxy:
            message += ' and proxy %(type)s://%(ip)s:%(port)s' % proxy
        logger.info(message)

        if server['protocol'] == 'doh_json':
            qn = request.q.qname
            qt = QTYPE[request.q.qtype]
            qn2 = str(qn).rstrip('.')
            url = '%s?name=%s&type=%s' % (server['ip'], qn2, qt)
            data = sendto_doh_json(
                url,
                proxy=proxy if server['proxy'] else None,
            )
            if data['Status'] == 0:
                if 'Answer' in data:
                    for record in data['Answer']:
                        reply.add_answer(dict2RR(record))
                if 'Authority' in data:
                    for record in data['Authority']:
                        reply.add_auth(dict2RR(record))
                if 'Additional' in data:
                    for record in data['Additional']:
                        reply.add_ar(dict2RR(record))
        elif server['protocol'] == 'doh' or server['protocol'] == 'doh_wireformat':
            # GET method: ignore
            # base64 encode DNS message. It will conflict URL encoding character
            # POST method
            # https is tunnel. It do not modifiy DNS message
            dns_message = sendto_doh_wireformat(
                server['ip'], data=request.pack(),
                proxy=proxy if server['proxy'] else None,
            )
            upstream_reply = DNSRecord.parse(dns_message)
            if upstream_reply.rr:
                for r in upstream_reply.rr:
                    rqn = r.rname
                    rqt = QTYPE[r.rtype]
                    if rqt in ['A', 'AAAA'] and str(r.rdata) in globalvars.bogus_nxdomain:
                        logger.warn('\t*** Bogus Answer: %s(%s) ***' % (r.rdata, rqt))
                        hack_ip = globalvars.config['smartdns']['bogus_nxdomain']['hack_ip']
                        if hack_ip:
                            hack_rqt = 'AAAA' if ':' in hack_ip else 'A'
                            hack_r = RR(
                                rname=rqn,
                                rtype=getattr(QTYPE, hack_rqt),
                                rclass=1, ttl=60 * 5,
                                rdata=getattr(dnslib, hack_rqt)(hack_ip),
                            )
                            reply.rr.append(hack_r)
                    else:
                        reply.add_answer(r)
        else:
            raise ValueError('Unknown protocol: %s' % server['protocol'])

        message = ['\tReturn from %(ip)s:%(port)s(%(priority)s):' % server]
        if globalvars.dig:
            logger.warn(str(reply))
        elif reply.rr:
            for r in reply.rr:
                message.append('\t\t%s(%s)' % (r.rdata, QTYPE[r.rtype]))
        else:
            message.append('\t\tN/A')
        logger.warn('\n'.join(message))
        return True
    except Exception as err:
        logger.error('%s' % err)
    return False


def sendto_doh_json(url, proxy=None):
    """ dns-query """
    r = urllib.request.Request(url)
    r.add_header('accept', 'application/dns-json')
    r.add_header('user-agent', 'Mozilla/5.0 (X11; Linux x86_64; rv:17.0) Gecko/20130619 Firefox/17.0')
    if proxy:
        opener = urllib.request.build_opener(SocksiPyHandler(
            socks.PROXY_TYPES[proxy['type'].upper()],
            proxy['ip'],
            proxy['port'],
        ))
        data_io = opener.open(r)
    else:
        data_io = urllib.request.urlopen(r)
    data = data_io.read()
    data = json.loads(data)
    return data


def sendto_doh_wireformat(url, data=None, proxy=None):
    """ dns-message """
    r = urllib.request.Request(url)
    r.add_header('accept', 'application/dns-message')
    r.add_header('content-type', 'application/dns-message')
    r.add_header('user-agent', 'Mozilla/5.0 (X11; Linux x86_64; rv:17.0) Gecko/20130619 Firefox/17.0')
    if proxy:
        opener = urllib.request.build_opener(SocksiPyHandler(
            socks.PROXY_TYPES[proxy['type'].upper()],
            proxy['ip'],
            proxy['port'],
        ))
        data_io = opener.open(r, data=data)
    else:
        data_io = urllib.request.urlopen(r, data=data)
    data = data_io.read()
    return data
