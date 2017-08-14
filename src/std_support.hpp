#pragma once

#include <string>
#include <sstream>

namespace std_support {

    template<typename T>
    std::string to_string(const T &n) {
        std::stringstream ss;
        ss << n;
        return ss.str();
    }

    double strtod(const char *str, char **endptr);

    int stoi(const std::string &str);

    long long strtoll(const char *str, char **endptr = nullptr, int base = 10);

    unsigned long long strtoull(const char *str, char **endptr = nullptr, int base = 10);
};