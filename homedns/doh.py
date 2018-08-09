
import logging
import json

import urllib.request

import socks
from sockshandler import SocksiPyHandler

import dnslib
from dnslib import RR, QTYPE, DNSRecord

from . import globalvars

logger = logging.getLogger(__name__)


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
                for r in data['Answer']:
                    answer = RR(
                        rname=r['name'],
                        rtype=r['type'],
                        rclass=1, ttl=r['TTL'],
                        rdata=getattr(dnslib, QTYPE[r['type']])(r['data']),
                    )
                    reply.add_answer(answer)
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
