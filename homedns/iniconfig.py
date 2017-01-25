#!/usr/bin/env python
# -*- encoding:utf-8 -*-

from six.moves.configparser import ConfigParser


def ini_read(config_file):
    def strip_item(l):
        return [x.strip() for x in l]

    cfg = ConfigParser()
    cfg.read(config_file, encoding='utf8')
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
        'hack_ip': cfg.get(section, 'hack_ip'),
    }
    section = 'proxy'
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
            'tcp': cfg.getboolean(section, 'tcp'),
            'priority': cfg.getint(section, 'priority'),
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
    line = []
    line.append('[log]')
    line.append('%s = %s' % ('file', config['log']['file']))
    line.append('%s = %s' % ('level', config['log']['level']))
    line.append('')

    line.append('[server]')
    line.append('# 协议类型: TCP, UDP')
    line.append('%s = %s' % ('protocols', ','.join(config['server']['protocols'])))
    line.append('# 服务地址和端口')
    line.append('%s = %s' % ('listen_ip', config['server']['listen_ip']))
    line.append('%s = %s' % ('listen_port', config['server']['listen_port']))
    line.append('# 搜索范围，本地还是远端: local, upstream')
    line.append('%s = %s' % ('search', ','.join(config['server']['search'])))
    line.append('# 允许访问的客户端范围: 192.168.1.0/24, 192.1682.10-100, 192.168.3.*')
    line.append('%s = %s' % ('allowed_hosts', ','.join(config['server']['allowed_hosts'])))
    line.append('')

    line.append('[smartdns]')
    line.append('# DNS 匹配规则, 按顺序匹配. 具体配置在 [rules_名字] 中')
    line.append('%s = %s' % ('rules', ','.join([x['name'] for x in config['smartdns']['rules']])))
    line.append('# 劫持 DNS 服务: _ldap._tcp, ...')
    line.append('%s = %s' % ('hack_srv', ','.join(config['smartdns']['hack_srv'])))
    line.append('')

    for rule in config['smartdns']['rules']:
        line.append('[rules_%s]' % rule['name'])
        line.append('# 配置文件位置, 本地或远端 URL')
        line.append('%s = %s' % ('url', rule['url']))
        line.append('# 从 URL 下载时是否使用代理, Ture/False')
        line.append('%s = %s' % ('proxy', rule['proxy']))
        line.append('# 文件自动更新时间间隔')
        line.append('%s = %s' % ('refresh', rule['refresh']))
        line.append('# 规则所使用的 DNS, 具体配置在 [dns_名字] 中')
        line.append('%s = %s' % ('dns', ','.join(rule['dns'])))
        line.append('')

    for name, value in config['smartdns']['upstreams'].items():
        line.append('[dns_%s]' % name)
        line.append('# 地址和端口, 如果 IP 为 DHCP, 则从 DHCP 服务器获取 DNS 地址')
        line.append('%s = %s' % ('ip', ','.join(value['ip'])))
        line.append('%s = %s' % ('port', value['port']))
        line.append('# 连接超时时间')
        line.append('%s = %s' % ('timeout', value['timeout']))
        line.append('# 是否使用代理, True/False')
        line.append('%s = %s' % ('proxy', value['proxy']))
        line.append('# 是否使用 TCP 模式, True/False')
        line.append('%s = %s' % ('tcp', value['tcp']))
        line.append('# 优先级')
        line.append('%s = %s' % ('priority', value['priority']))
        line.append('')

    line.append('[bogus_nxdomain]')
    line.append('# bogus 文件位置, 本地或远端 URL')
    line.append('%s = %s' % ('url', config['smartdns']['bogus_nxdomain']['url']))
    line.append('# 从 URL 下载时是否使用代理, Ture/False')
    line.append('%s = %s' % ('proxy', config['smartdns']['bogus_nxdomain']['proxy']))
    line.append('# 文件自动更新时间间隔')
    line.append('%s = %s' % ('refresh', config['smartdns']['bogus_nxdomain']['refresh']))
    line.append('# 劫持 bogus')
    line.append('%s = %s' % ('hack_ip', config['smartdns']['bogus_nxdomain']['hack_ip']))
    line.append('')

    line.append('[proxy]')
    line.append('# 代理类型, SOCKS5/HTTP')
    line.append('%s = %s' % ('type', config['smartdns']['proxy']['type']))
    line.append('# 服务器地址和端口')
    line.append('%s = %s' % ('ip', config['smartdns']['proxy']['ip']))
    line.append('%s = %s' % ('port', config['smartdns']['proxy']['port']))
    line.append('')

    line.append('[domains]')
    line.append('# 本地域, 支持 DNS域记录和 hosts 文件格式, 具体配置在 [domain_名字] 中')
    line.append('%s = %s' % ('domain', ','.join([x['name'] for x in config['domains']])))
    line.append('')

    for domain in config['domains']:
        line.append('[domain_%s]' % domain['name'])
        line.append('# 域名')
        line.append('%s = %s' % ('name', domain['name']))
        line.append('# 域文件位置, 本地或远端 URL')
        line.append('%s = %s' % ('url', domain['url']))
        line.append('# 从 URL 下载时是否使用代理, Ture/False')
        line.append('%s = %s' % ('proxy', domain['proxy']))
        line.append('# 域类型, dns/hosts')
        line.append('%s = %s' % ('type', domain['type']))
        line.append('# 文件自动更新时间间隔')
        line.append('%s = %s' % ('refresh', domain['refresh']))
        line.append('')

    with open(config_file, 'w') as f:
        f.write('\n'.join(line))
