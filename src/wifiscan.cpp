#include "include/logger.h"
#include "include/wifiscan.h"
#include <iostream>
#include <string.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>

WiFiScan::WiFiScan(char* interface)
{
    strcpy(intf_name, interface);
}

void WiFiScan::start_scan()
{
    int if_index = interface_to_index(intf_name);
}

int WiFiScan::interface_to_index(char* interface)
{
    // Use this wireless interface for scanning.
    int if_index = if_nametoindex(interface);
    if (if_index == 0)
    {
        Logger::printLog(LOG_ERROR, (char*)"Error, entered wrong name of interface name.");
        std::cout << "Error, entered wrong name of interface name." << std::endl;
        exit(-2);
    }
    Logger::printLog(LOG_DEBUG, (char*)"Created index for interface %s = %d", interface, if_index);
    return if_index;
}

struct nl_sock* WiFiScan::open_socket()
{
    // Open socket to kernel.
    struct nl_sock *socket = nl_socket_alloc();  // Allocate new netlink socket in memory.
    genl_connect(socket);  // Create file descriptor and bind socket.
    return socket;
}
