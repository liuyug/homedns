@echo off

echo Current DNS server
echo ------------------
netsh interface ipv4 show dnsserver

set server=127.0.0.1

echo Change DNS Ipaddress
echo     netsh interface ipv4 set dnsservers "WLAN" static %server% primary

echo or change to DHCP
echo     netsh interface ipv4 set dnsservers "WLAN" dhcp
echo     ipconfig /flushdns
