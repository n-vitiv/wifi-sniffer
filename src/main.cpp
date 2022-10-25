#include <iostream>
#include "include/logger.h"
#include "include/wifiscan.h"

int main(int argc, char**argv)
{
    if (argc < 2)
    {
        Logger::printLog(LOG_ERROR, (char*)"Incorrect number of arguments %d %f %s", 2, 4.55, "123");
        std::cout << "Should be entered interface name. Example: wifi-sniffer <intf_name>" << std::endl;
        return -1;
    }

    return 0;
}
