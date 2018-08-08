
import logging
import json

import urllib.request

import socks
from sockshandler import SocksiPyHandler

import dnslib
from dnslib import RR, QTYPE

from . import globalvars

logger = logging.getLogger(__name__)


def lookup_upstream_by_doh(request, reply, server, proxy):
    try:
        message = '\tForward to server %(ip)s(%(priority)s)' % server
        message += ' with %s protocol' % server['protocol']
        if server['proxy'] and proxy:
                message += ' and proxy %(type)s://%(ip)s:%(port)s' % proxy
        logger.info(message)

        qn = request.q.qname
        qt = QTYPE[request.q.qtype]
        qn2 = str(qn).rstrip('.')
        url = '%s?name=%s&type=%s' % (server['ip'], qn2, qt)

        data = sendto_doh(
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
        logger.warn('\tReturn from %(ip)s:%(port)s(%(priority)s):' % server)
        if globalvars.dig:
            logger.warn(str(reply))
        elif reply.rr:
            for r in reply.rr:
                logger.warn('\t\t%s(%s)' % (r.rdata, QTYPE[r.rtype]))
        else:
            logger.warn('\t\tN/A')
        return True
    except Exception as err:
        logger.error('error: %s' % err)
    return False


def sendto_doh(url, proxy=None):
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
