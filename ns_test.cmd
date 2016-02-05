
@echo off

cls
set SERVER=%1

echo ===============
echo HomeDNS testing
echo ===============
echo on

@echo off
echo --------------
echo test subdomain
echo --------------
echo on
nslookup ldap %SERVER%

@echo off
echo ------------------
echo test hosts.homedns
echo ------------------
echo on
nslookup unknown.cisco.com %SERVER%

@echo off
echo ---------------
echo test white list
echo ---------------
echo on
nslookup www.cisco.com %SERVER%

@echo off
echo ---------------
echo test black list
echo ---------------
echo on
nslookup www.goolge.com %SERVER%

@echo off
echo ---------------
echo test TXT record
echo ---------------
echo on
nslookup -type=txt mylocal.home %SERVER%

@echo off
echo ---------------------
echo test local SRV record
echo ---------------------
echo on
nslookup -type=srv _ldap._tcp %SERVER%

@echo off
echo ----------------------
echo test remote SRV record
echo ----------------------
echo will be change to local domain
echo on
nslookup -type=srv _ldap._tcp.cisco.com %SERVER%
