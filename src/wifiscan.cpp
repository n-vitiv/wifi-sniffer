#include "include/logger.h"
#include "include/wifiscan.h"
#include <iostream>

int interface_to_index(char* interface)
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
