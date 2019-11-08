#!/usr/bin/env python3
# -*- encoding:utf-8 -*-

import json

import requests


def main():
    url = 'https://blog.bgme.me/listings/domain_list_poisoning.json'
    response = requests.get(url)
    domains = json.loads(response.text)
    with open('gfw_dns_poisoning.rules', 'wt') as f:
        for d in domains:
            f.write('||%s\n' % d.strip('.'))


if __name__ == '__main__':
    main()
