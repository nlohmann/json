#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace nlohmann::literals;

// function to print UBJSON's diagnostic format
void print_byte(uint8_t byte)
{
    if (32 < byte and byte < 128)
    {
        std::cout << (char)byte;
    }
    else
    {
        std::cout << (int)byte;
    }
}

int main()
{
    // create a JSON value
    json j = R"({"compact": true, "schema": false})"_json;

    // serialize it to UBJSON
    std::vector<std::uint8_t> v = json::to_ubjson(j);

    // print the vector content
    for (auto& byte : v)
    {
        print_byte(byte);
    }
    std::cout << std::endl;

    // create an array of numbers
    json array = {1, 2, 3, 4, 5, 6, 7, 8};

    // serialize it to UBJSON using default representation
    std::vector<std::uint8_t> v_array = json::to_ubjson(array);
    // serialize it to UBJSON using size optimization
    std::vector<std::uint8_t> v_array_size = json::to_ubjson(array, true);
    // serialize it to UBJSON using type optimization
    std::vector<std::uint8_t> v_array_size_and_type = json::to_ubjson(array, true, true);

    // print the vector contents
    for (auto& byte : v_array)
    {
        print_byte(byte);
    }
    std::cout << std::endl;

    for (auto& byte : v_array_size)
    {
        print_byte(byte);
    }
    std::cout << std::endl;

    for (auto& byte : v_array_size_and_type)
    {
        print_byte(byte);
    }
    std::cout << std::endl;
}
