#ifndef LOGGER_H
#define LOGGER_H
#include <fstream>
#include <stdio.h>

//enum with logs types
enum logLevel
{
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR,
};

class Logger
{
private:
    //std::fstream Log;
    FILE *Log;
    //singleton
    static Logger instance;
    static std::string levelToString(logLevel level);
    static std::string getCurrentTime();

public:
    Logger();
    ~Logger();
    static void printLog(logLevel level, char* msg, ...);
};
#endif
