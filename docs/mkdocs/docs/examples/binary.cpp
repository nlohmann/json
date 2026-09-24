#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a binary vector
    std::vector<std::uint8_t> vec = {0xCA, 0xFE, 0xBA, 0xBE};

    // create a binary JSON value with subtype 42
    json j = json::binary(vec, 42);

    // output type and subtype
    std::cout << "type: " << j.type_name() << ", subtype: " << j.get_binary().subtype() << std::endl;
}
