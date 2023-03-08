#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // a valid JSON text
    auto valid_text = R"(
    {
        "numbers": [1, 2, 3]
    }
    )";

    // an invalid JSON text
    auto invalid_text = R"(
    {
        "strings": ["extra", "comma", ]
    }
    )";

    std::cout << std::boolalpha
              << json::accept(valid_text) << ' '
              << json::accept(invalid_text) << '\n';
}
