#include <iostream>
#include <nlohmann/json.hpp>

using nlohmann::json;

int main()
{
    json::json_pointer::string_t s = "This is a string.";

    std::cout << s << '\n';

    std::cout << std::boolalpha << std::is_same<json::json_pointer::string_t, json::string_t>::value << '\n';
}
