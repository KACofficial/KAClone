

#ifndef UTILS_HPP
#define UTILS_HPP

#include <ctime>
#include <argparse/argparse.hpp>


#define VERBOSE_LOG(message)                                       \
    do {                                                          \
        auto now = std::chrono::system_clock::now();            \
        std::time_t now_time = std::chrono::system_clock::to_time_t(now); \
        std::tm* local_time = std::localtime(&now_time);         \
        std::cout << "[" << std::put_time(local_time, "%H:%M:%S") << "] " \
                  << message << std::endl;                      \
    } while(0)

void startBackupTool(argparse::ArgumentParser& parser);

#endif
