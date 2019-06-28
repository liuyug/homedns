#!/usr/bin/env python3
# -*- encoding:utf-8 -*-

import sys
import requests

import lxml.html


def get_dns_ip_cn():
    headers = {}
    headers['user-agent'] = 'Mozilla/6.0'
    ret = requests.get('http://dns.ip.cn', headers=headers)
    if ret.status_code != 200:
        print('[ERROR] HTTP code: %s' % ret.status_code, file=sys.stderr)
        return
    ret.encoding = 'utf-8'
    html = ret.text

    ip_cn_dns = {}
    root = lxml.html.fromstring(html)
    for node in root.xpath('//h4'):
        title = node.xpath('string(.)')
        ip_cn_dns[title] = []
        table = node.xpath('./following-sibling::div[1]/table')
        site = []
        for tr in table[0].xpath('.//tr'):
            name = tr.xpath('string(./td[1])').strip()
            dns1 = tr.xpath('string(./td[2])').strip()
            dns2 = tr.xpath('string(./td[3])').strip()
            if not dns1:
                continue
            site.append(name)
            site.append(dns1)
            if dns2:
                site.append(dns2)
            if not tr.xpath('./td[1]/@rowspan'):
                ip_cn_dns[title].append(site)
                site = []
    return ip_cn_dns


def main():
    dns = get_dns_ip_cn()
    import pprint
    pprint.pprint(dns)


if __name__ == '__main__':
    main()
