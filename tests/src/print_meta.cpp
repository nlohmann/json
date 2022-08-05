//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.10.5
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2022 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include <iostream>

#ifdef JSON_TEST_PRINT_META_WITH_MAIN
    #include <nlohmann/json.hpp>
#endif

#define STRINGIZE_EX(x) #x
#define STRINGIZE(x) STRINGIZE_EX(x)

void print_meta();

void print_meta()
{
    auto meta = nlohmann::ordered_json::meta();
    meta.erase("name");
    meta.erase("url");
    meta.erase("copyright");
    meta["version"] = meta["version"]["string"];

    // strip off the parentheses added to silence clang-tidy warning
    auto strip_parens = [](const std::string & str)
    {
        return (str[0] == '(') ? std::string(str.data() + 1, str.size() - 2) : str;
    };
    std::cout << strip_parens(STRINGIZE(JSON_TEST_NAME)) << '\n';
    std::cout << meta.dump(4) << '\n' << std::endl;
}

#ifdef JSON_TEST_PRINT_META_WITH_MAIN
int main(int  /*argc*/, char*  /*argv*/[])
{
    print_meta();

    return 0;
}
#endif
