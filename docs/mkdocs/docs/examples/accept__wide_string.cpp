#include <iostream>
#include <string>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // a valid JSON text, given as UTF-16
    const std::u16string valid_text = u"{\"name\":\"\u00e9\"}";

    // an invalid JSON text, given as UTF-16
    const std::u16string invalid_text = u"{\"name\":\"\u00e9\",}";

    std::cout << std::boolalpha
              << json::accept(valid_text) << ' '
              << json::accept(invalid_text) << '\n';
}
