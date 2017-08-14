#include "std_support.hpp"
#include <cstdlib>

unsigned long long std_support::strtoull(const std::string &str, char **endptr, int base) {
    std::stringstream ss(str);
    unsigned long long val;
    ss >> val;
    return val;
}

long long std_support::strtoll(const std::string &str, char **endptr, int base) {
    std::stringstream ss(str);
    long long val;
    ss >> val;
    return val;
}

int std_support::stoi(const std::string &str) {
    return std::atoi(str.c_str());
}

double std_support::strtod(const char *str, char **endptr) {
    return std::strtod(str, endptr);
}