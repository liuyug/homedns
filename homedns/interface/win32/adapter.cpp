#include <Winsock2.h>
#include <WS2tcpip.h>
#include <Iphlpapi.h>

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <vector>

#include "adapter.h"

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))


AdapterInfo::AdapterInfo()
{
    // Initialize Winsock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    this->initialize();
}

AdapterInfo::~AdapterInfo()
{
    WSACleanup();
}

int AdapterInfo::initialize()
{
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR) {
        return WSAGetLastError();
    }
    this->hostname = std::string(hostname);
    return 0;
}

std::vector<PADAPTER_INFO> AdapterInfo::get()
{
    std::vector<PADAPTER_INFO> interfaces;

    ULONG flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS;
    ULONG family = AF_UNSPEC;

    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
    PIP_ADAPTER_UNICAST_ADDRESS pUnicast = NULL;
    PIP_ADAPTER_ANYCAST_ADDRESS pAnycast = NULL;
    PIP_ADAPTER_MULTICAST_ADDRESS pMulticast = NULL;
    IP_ADAPTER_DNS_SERVER_ADDRESS *pDnsServer = NULL;
    IP_ADAPTER_PREFIX *pPrefix = NULL;
    PIP_ADAPTER_GATEWAY_ADDRESS_LH pGateway = NULL;


    ULONG outBufLen = 10 * 1024;
    DWORD dwRetVal = 0;

    int count = 0;
    int max_tries = 3;
    do {
        pAddresses = (IP_ADAPTER_ADDRESSES *) MALLOC(outBufLen);
        if (pAddresses == NULL) {
            return interfaces;
        }

        dwRetVal =
            GetAdaptersAddresses(family, flags, NULL, pAddresses, &outBufLen);

        if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
            FREE(pAddresses);
            pAddresses = NULL;
        } else {
            break;
        }
        count++;
    } while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (count < max_tries));

    if (dwRetVal != NO_ERROR) return interfaces;

    unsigned int i = 0;

    PADAPTER_INFO iface;

    pCurrAddresses = pAddresses;
    while (pCurrAddresses) {
        iface = new ADAPTER_INFO;
        ZeroMemory(iface, sizeof(ADAPTER_INFO));

        iface->name = pCurrAddresses->AdapterName;

        iface->dnsSuffix = pCurrAddresses->DnsSuffix;
        iface->description = pCurrAddresses->Description;

        char buff[8];
        for (i = 0; i < (int) pCurrAddresses->PhysicalAddressLength; i++) {
            sprintf_s(buff, sizeof(buff),
                    "%02X", (int) pCurrAddresses->PhysicalAddress[i]);
            iface->physicalAddr.append(buff);
            if (i < (pCurrAddresses->PhysicalAddressLength - 1))
                iface->physicalAddr.append(":");
        }

        iface->mtu = pCurrAddresses->Mtu;

        iface->status = pCurrAddresses->OperStatus == IfOperStatusUp;
        iface->ipv4Enabled = (pCurrAddresses->Flags & IP_ADAPTER_IPV4_ENABLED) > 0;
        iface->ipv6Enabled = (pCurrAddresses->Flags & IP_ADAPTER_IPV6_ENABLED) > 0;
        iface->dhcpEnabled = (pCurrAddresses->Flags & IP_ADAPTER_DHCP_ENABLED) > 0;

        if (iface->status) {
            iface->txSpeed = (unsigned long) pCurrAddresses->TransmitLinkSpeed / 1000 / 1000;
            iface->rxSpeed = (unsigned long) pCurrAddresses->ReceiveLinkSpeed / 1000 / 1000;

            pUnicast = pCurrAddresses->FirstUnicastAddress;
            if (pUnicast != NULL) {
                for (i = 0; pUnicast != NULL; i++) {
                    iface->addrUnicast.push_back(
                            formatSockaddr(pUnicast->Address.lpSockaddr));
                    pUnicast = pUnicast->Next;
                }
            }

            pAnycast = pCurrAddresses->FirstAnycastAddress;
            if (pAnycast != NULL) {
                for (i = 0; pAnycast != NULL; i++) {
                    iface->addrAnycast.push_back(
                            formatSockaddr(pAnycast->Address.lpSockaddr));
                    pAnycast = pAnycast->Next;
                }
            }

            pMulticast = pCurrAddresses->FirstMulticastAddress;
            if (pMulticast != NULL) {
                for (i = 0; pMulticast != NULL; i++) {
                    iface->addrMulticast.push_back(
                            formatSockaddr(pMulticast->Address.lpSockaddr));
                    pMulticast = pMulticast->Next;
                }
            }

            pDnsServer = pCurrAddresses->FirstDnsServerAddress;
            if (pDnsServer != NULL) {
                for (i = 0; pDnsServer != NULL; i++) {
                    iface->addrDnsServer.push_back(
                            formatSockaddr(pDnsServer->Address.lpSockaddr));
                    pDnsServer = pDnsServer->Next;
                }
            }
            pGateway = pCurrAddresses->FirstGatewayAddress;
            if (pGateway != NULL) {
                for (i = 0; pGateway != NULL; i++) {
                    iface->addrGateway.push_back(
                            formatSockaddr(pGateway->Address.lpSockaddr));
                    pGateway = pGateway->Next;
                }
            }
            iface->ipv4Metric = pCurrAddresses->Ipv4Metric;
            iface->ipv6Metric = pCurrAddresses->Ipv6Metric;
            if (iface->dhcpEnabled) {
                if (iface->ipv4Enabled &&
                        pCurrAddresses->Dhcpv4Server.lpSockaddr != NULL) {
                    iface->addrDhcp.push_back(
                            formatSockaddr(pCurrAddresses->Dhcpv4Server.lpSockaddr));
                }
                if (iface->ipv6Enabled &&
                        pCurrAddresses->Dhcpv6Server.lpSockaddr != NULL) {
                    iface->addrDhcp.push_back(
                            formatSockaddr(pCurrAddresses->Dhcpv6Server.lpSockaddr));
                }

            }
        }

        interfaces.push_back(iface);
        pCurrAddresses = pCurrAddresses->Next;
    }
    if (pAddresses) {
        FREE(pAddresses);
    }
    return interfaces;
}

std::string AdapterInfo::formatSockaddr(SOCKADDR * addr)
{
    char buff[256];
    buff[0] = '\0';
    if (addr->sa_family == AF_INET) {
        SOCKADDR_IN * addr_in = (SOCKADDR_IN*)addr;
        inet_ntop(AF_INET, &(addr_in->sin_addr), buff, sizeof(buff));
    } else if (addr->sa_family == AF_INET6) {
        SOCKADDR_IN6 * addr_in6 = (SOCKADDR_IN6*)addr;
        inet_ntop(AF_INET6, &(addr_in6->sin6_addr), buff, sizeof(buff));
    }
    return std::string(buff);
}


int main(int argc, char **argv)
{
    AdapterInfo ai = AdapterInfo();
    ai.get();
    std::cout << "Hostname: " << ai.hostname << std::endl;
}
