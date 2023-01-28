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

    static int family_handler(struct nl_msg *msg, void *arg);
    int interface_to_index(char* interface);
    int nl_get_multicast_id(struct nl_sock *sock, const char *family, const char *group);
    struct nl_sock* open_socket();
    WiFiScan();
    int trigger_scan(struct nl_sock *socket, int if_index, int driver_id);
};


#endif
