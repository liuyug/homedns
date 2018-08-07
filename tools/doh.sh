#!/bin/bash

host=$1

if [ x"$host" = "x" ]; then
    host=www.google.com
fi

declare -A dns_provider=(
[Goolge]='https://dns.google.com/resolve'
[CloudFlare]='https://cloudflare-dns.com/dns-query'
[Blahdns]='https://doh.blahdns.com/dns-query'
[Blahdns(DE)]='https://doh.de.blahdns.com/dns-query'
)

keys=${!dns_provider[@]}

for key in ${keys[@]}; do
    echo "$key (${dns_provider[$key]})"
    dns=${dns_provider[$key]}
    time curl -H 'accept: application/dns-json' "$dns?name=$host"
done

# vim: tabstop=4 shiftwidth=4 expandtab
