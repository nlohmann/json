//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

import std;
import nlohmann.json;

using namespace nlohmann::literals;

// Exercise the surface exported by the nlohmann.json module so that a missing
// or broken export is caught at compile time.
//
// Standard-library facilities are pulled in via `import std;` rather than
// textual `#include`s: mixing `import` with textual standard headers does not
// compile under GCC's C++20 modules implementation, whereas `import std;` works
// across GCC, Clang, and MSVC. This requires C++23 and CMake's (experimental)
// import-std support; see CMakeLists.txt.
int main()
{
    // basic_json / json: parsing and value access
    nlohmann::json j = nlohmann::json::parse(R"({"a": 1, "list": [1, 2, 3]})");
    const int a = j["a"].get<int>();

    // json_pointer and operator""_json_pointer
    nlohmann::json_pointer<std::string> ptr = "/list/2"_json_pointer;
    const int last = j[ptr].get<int>();

    // operator""_json literal
    const nlohmann::json lit = R"([1, 2, 3])"_json;

    // ordered_json
    nlohmann::ordered_json oj;
    oj["b"] = 2;
    const int b = oj["b"].get<int>();

    // ordered_map alias
    nlohmann::ordered_map<std::string, int> m;
    m["x"] = 1;

    // adl_serializer (reference the exported template)
    using serializer = nlohmann::adl_serializer<int, void>;
    static_cast<void>(sizeof(serializer));

    // to_string
    const std::string dumped = nlohmann::to_string(j);

    // operator<< (hidden friend, reached via ADL through the module)
    std::ostringstream os;
    os << j << oj << lit;

    // use every result so the references cannot be optimized away
    return (a == 1 && last == 3 && b == 2 && lit.size() == 3
            && m.size() == 1 && !dumped.empty() && !os.str().empty())
        ? 0 : 1;
}
