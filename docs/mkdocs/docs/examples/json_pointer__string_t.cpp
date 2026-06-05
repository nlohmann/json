#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    json::json_pointer::string_t s = "This is a string.";

    std::cout << s << std::endl;

    std::cout << std::boolalpha << std::is_same<json::json_pointer::string_t, json::string_t>::value << std::endl;
}
