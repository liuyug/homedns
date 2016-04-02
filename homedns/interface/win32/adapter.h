#ifndef __ADAPTER__
#define __ADAPTER__

#include <string>
#include <vector>

#include "Winsock2.h"

typedef std::vector<std::string> StringVector;

typedef struct _ADAPTERINFO {
    std::string name;
    StringVector addrUnicast;
    StringVector addrAnycast;
    StringVector addrMulticast;
    StringVector addrDnsServer;
    std::wstring dnsSuffix;
    std::wstring description;
    std::string physicalAddr;
    int mtu;
    bool status;
    unsigned long txSpeed;
    unsigned long rxSpeed;
    StringVector addrGateway;
    ULONG ipv4Metric;
    ULONG ipv6Metric;
    bool dhcpEnabled;
    StringVector addrDhcp;

    bool ipv4Enabled;
    bool ipv6Enabled;
} ADAPTER_INFO, * PADAPTER_INFO;


class AdapterInfo
{
    public:
        AdapterInfo();
        ~AdapterInfo();

        std::vector<PADAPTER_INFO> get();

        std::string hostname;
    protected:
        int initialize();

    private:
        std::string formatSockaddr(SOCKADDR * addr);

};

#endif
