#include "include/logger.h"
#include <ctime>
#include <algorithm>
#include <stdarg.h>
#include <iostream>
#include <sys/stat.h>


Logger Logger::instance;

Logger::Logger()
{
    mkdir("logs", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    instance.Log = fopen("logs/logs.log", "w+");
    if (instance.Log == NULL)
    {
        std::cout << ("Can`t open file for logs.") << std::endl;
    }
}

Logger::~Logger()
{
    if (instance.Log != NULL)
    {
        fclose(instance.Log);
    }
}

void Logger::printLog(logLevel level, char* msg, ...)
{
    va_list args;
    va_start(args, msg);

    if (instance.Log == NULL)
    {
        std::cout << "Can`t print logs. Log file is closed." << std::endl;
        return;
    }

    std::string time = getCurrentTime();
    std::string logType = levelToString(level);
    std::string result = time + logType + msg + "\n";

    vfprintf(instance.Log, result.c_str(), args);
    va_end(args);
}

std::string Logger::levelToString(logLevel level)
{
    switch(level)
    {
        case LOG_ERROR :
            return " ERROR : ";
            break;
        case LOG_WARNING :
            return " WARNING : ";
            break;
        case LOG_INFO :
            return " INFO : ";
            break;
        case LOG_DEBUG :
            return " DEBUG : ";
            break;
        default :
            return " Bad type : ";
            break;
    }
}

std::string Logger::getCurrentTime()
{
    time_t current_time;
    time(&current_time);
    std::string res = std::ctime(&current_time);
    res.erase(std::remove(res.begin(), res.end(), '\n'), res.end());
    return res;
}
