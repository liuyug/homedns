
import binascii
import logging


from . import globalvars
from dnslib import RR, QTYPE, DNSRecord, DNSHeader, DNSLabel

from . import dns
from . import doh

logger = logging.getLogger(__name__)


def lookup_local(request, reply):
    qn2 = qn = request.q.qname
    qt = QTYPE[request.q.qtype]

    indomain = False

    for value in globalvars.local_domains.values():
        domain = value['domain']
        if globalvars.config['smartdns']['hack_srv'] and qt == 'SRV' and \
                not domain.inDomain(qn2):
            r_srv = b'.'.join(qn.label[:2])
            if r_srv.decode().lower() in globalvars.config['smartdns']['hack_srv']:
                qn2 = DNSLabel(domain.get_subdomain('@')).add(r_srv)
                logger.warn('\tChange SRV request to %s from %s' % (qn2, qn))

        if domain.inDomain(qn2):
            indomain = True
            logger.warn('\tRequest "%s(%s)" is in "local" list.' % (qn, qt))
            rr_data = domain.search(qn2, qt)
            if rr_data:
                for r in rr_data:
                    answer = RR(
                        rname=r['name'],
                        rtype=getattr(QTYPE, r['type']),
                        rclass=1, ttl=60 * 5,
                        rdata=r['rdata'],
                    )
                    reply.add_answer(answer)

                    if r['type'] == 'CNAME' and not domain.inDomain(r['rdata'].get_label()):
                        logger.warn('\tOutside alias "%s"' % r['rdata'])
                        alias_request = DNSRecord.question(str(r['rdata']))
                        alias_reply = DNSRecord(
                            DNSHeader(id=alias_request.header.id, qr=1, aa=1, ra=1),
                            q=alias_request.q
                        )
                        lookup_upstream(alias_request, alias_reply)
                        for r in alias_reply.rr:
                            reply.add_answer(r)
                break

    # log
    if indomain:
        logger.warn('\tReturn from LOCAL:')
        if globalvars.dig:
            logger.warn(str(reply))
        elif reply.rr:
            for r in reply.rr:
                logger.warn('\t\t%s(%s)' % (r.rdata, QTYPE[r.rtype]))
        else:
            logger.warn('\t\tN/A')

    return indomain


def lookup_upstream(request, reply):
    qn = request.q.qname
    qt = QTYPE[request.q.qtype]
    proxy = globalvars.config['smartdns']['proxy']
    qn2 = str(qn).rstrip('.')

    for name, param in globalvars.rules.items():
        if param['rule'].isBlock(qn2):
            logger.warn('\tRequest "%s(%s)" is in "%s" list.' % (qn, qt, name))
            servers = []
            for group in param['upstreams']:
                servers.extend(globalvars.upstreams[group])
            servers.sort(key=lambda x: x['priority'], reverse=True)
            for server in servers:
                # try query servers by priority
                ret = None
                if server['protocol'] == 'dns':
                    ret = dns.lookup_upstream(request, reply, server, proxy)
                elif server['protocol'] == 'doh':
                    ret = doh.lookup_upstream(request, reply, server, proxy)
                if ret:
                    if reply.rr:
                        # find and return
                        server['priority'] = min(server['priority'] + 5, 100)
                        return
                else:
                    # socket timeout
                    server['priority'] = int(server['priority'] / 2)

            # only use first matching rule
            break
    return


def dns_response(handler, data):
    try:
        request = DNSRecord.parse(data)
    except Exception as err:
        logger.error('Parse request error: %s %s %s' % (
            err, len(data), binascii.b2a_hex(data)))
        return

    reply = DNSRecord(
        DNSHeader(id=request.header.id, qr=1, aa=1, ra=1),
        q=request.q
    )

    if 'local' in globalvars.config['server']['search']:
        indomain = lookup_local(request, reply)
    if not indomain and 'upstream' in globalvars.config['server']['search']:
        lookup_upstream(request, reply)

    handler.send_data(reply.pack())

    # update
    for value in globalvars.rules.values():
        rule = value['rule']
        if rule.isNeedUpdate(value['refresh']):
            rule.async_update()
    for value in globalvars.local_domains.values():
        domain = value['domain']
        if domain.isNeedUpdate(value['refresh']):
            domain.async_update()
