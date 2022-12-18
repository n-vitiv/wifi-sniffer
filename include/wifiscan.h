#ifndef WIFISCAN_H
#define WIFISCAN_H

#include <net/if.h>
#include <string>
#include <iostream>

#define INTF_SIZE 16

class WiFiScan
{
public:
    WiFiScan(char* interface);
    void start_scan();

private:
    char intf_name[INTF_SIZE];

    int interface_to_index(char* interface);
    struct nl_sock* open_socket();
    WiFiScan();
};


#endif
