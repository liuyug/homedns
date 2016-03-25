#!/usr/bin/env python
# -*- encoding:utf-8 -*-

try:
    # py3
    from configparser import ConfigParser
except:
    # py2
    from ConfigParser import ConfigParser


def ini_read(config_file):
    def strip_item(l):
        return [x.strip() for x in l]

    cfg = ConfigParser()
    cfg.read(config_file)
    log = {}
    log['file'] = cfg.get('log', 'file')
    log['level'] = cfg.getint('log', 'level')
    server = {}
    server['protocols'] = strip_item(cfg.get('server', 'protocols').split(','))
    server['listen_ip'] = cfg.get('server', 'listen_ip')
    server['listen_port'] = cfg.getint('server', 'listen_port')
    server['search'] = strip_item(cfg.get('server', 'search').split(','))
    server['allowed_hosts'] = strip_item(cfg.get('server', 'allowed_hosts').split(','))
    smartdns = {}
    smartdns['rules'] = []
    for rule in strip_item(cfg.get('smartdns', 'rules').split(',')):
        section = 'rules_' + rule
        smartdns['rules'].append({
            'name': rule,
            'url': cfg.get(section, 'url'),
            'proxy': cfg.getboolean(section, 'proxy'),
            'refresh': cfg.getint(section, 'refresh'),
            'dns': strip_item(cfg.get(section, 'dns').split(',')),
        })
    smartdns['hack_srv'] = strip_item(cfg.get('smartdns', 'hack_srv').split(','))
    section = 'bogus_nxdomain'
    smartdns['bogus_nxdomain'] = {
        'url': cfg.get(section, 'url'),
        'proxy': cfg.getboolean(section, 'proxy'),
        'refresh': cfg.getint(section, 'refresh'),
    }
    section = cfg.get('smartdns', 'proxy')
    smartdns['proxy'] = {
        'type': cfg.get(section, 'type'),
        'ip': cfg.get(section, 'ip'),
        'port': cfg.getint(section, 'port'),
    }
    smartdns['upstreams'] = {}
    names = set()
    for rule in smartdns['rules']:
        names |= set(rule['dns'])
    for name in names:
        section = 'dns_' + name.strip()
        smartdns['upstreams'][name] = {
            'ip': cfg.get(section, 'ip').split(','),
            'port': cfg.getint(section, 'port'),
            'timeout': cfg.getint(section, 'timeout'),
            'proxy': cfg.getboolean(section, 'proxy'),
        }
    domains = []
    for name in strip_item(cfg.get('domains', 'domain').split(',')):
        section = 'domain_' + name
        domains.append({
            'name': cfg.get(section, 'name'),
            'url': cfg.get(section, 'url'),
            'proxy': cfg.getboolean(section, 'proxy'),
            'type': cfg.get(section, 'type'),
            'refresh': cfg.getint(section, 'refresh'),
        })
    config = {
        'log': log,
        'server': server,
        'smartdns': smartdns,
        'domains': domains,
    }
    return config


def ini_write(config, config_file):
    cfg = ConfigParser()
    cfg.add_section('log')
    cfg.set('log', 'file', config['log']['file'])
    cfg.set('log', 'level', str(config['log']['level']))
    cfg.add_section('server')
    cfg.set('server', 'protocols', ','.join(config['server']['protocols']))
    cfg.set('server', 'listen_ip', config['server']['listen_ip'])
    cfg.set('server', 'listen_port', str(config['server']['listen_port']))
    cfg.set('server', 'search', ','.join(config['server']['search']))
    cfg.set('server', 'allowed_hosts', ','.join(config['server']['allowed_hosts']))
    cfg.add_section('smartdns')
    cfg.set('smartdns', 'rules', ','.join([x['name'] for x in config['smartdns']['rules']]))
    for rule in config['smartdns']['rules']:
        section = 'rules_' + rule['name']
        cfg.add_section(section)
        cfg.set(section, 'url', rule['url'])
        cfg.set(section, 'proxy', str(rule['proxy']))
        cfg.set(section, 'refresh', str(rule['refresh']))
        cfg.set(section, 'dns', ','.join(rule['dns']))
    cfg.set('smartdns', 'hack_srv', ','.join(config['smartdns']['hack_srv']))
    cfg.add_section('bogus_nxdomain')
    cfg.set('bogus_nxdomain', 'url', config['smartdns']['bogus_nxdomain']['url'])
    cfg.set('bogus_nxdomain', 'proxy', str(config['smartdns']['bogus_nxdomain']['proxy']))
    cfg.set('bogus_nxdomain', 'refresh', str(config['smartdns']['bogus_nxdomain']['refresh']))
    cfg.set('smartdns', 'proxy', 'proxy')
    cfg.add_section('proxy')
    cfg.set('proxy', 'type', config['smartdns']['proxy']['type'])
    cfg.set('proxy', 'ip', config['smartdns']['proxy']['ip'])
    cfg.set('proxy', 'port', str(config['smartdns']['proxy']['port']))
    for name, value in config['smartdns']['upstreams'].items():
        section = 'dns_' + name
        cfg.add_section(section)
        cfg.set(section, 'ip', ','.join(value['ip']))
        cfg.set(section, 'port', str(value['port']))
        cfg.set(section, 'timeout', str(value['timeout']))
        cfg.set(section, 'proxy', str(value['proxy']))
    cfg.add_section('domains')
    cfg.set('domains', 'domain', ','.join([x['name'] for x in config['domains']]))
    for domain in config['domains']:
        section = 'domain_' + domain['name']
        cfg.add_section(section)
        cfg.set(section, 'name', domain['name'])
        cfg.set(section, 'url', domain['url'])
        cfg.set(section, 'proxy', str(domain['proxy']))
        cfg.set(section, 'type', domain['type'])
        cfg.set(section, 'refresh', str(domain['refresh']))
    cfg.write(open(config_file, 'w'))
