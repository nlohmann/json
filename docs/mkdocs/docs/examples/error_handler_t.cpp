#include <iomanip>
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON value with invalid UTF-8 byte sequence
    json j_invalid = "ä\xA9ü";
    try
    {
        std::cout << j_invalid.dump() << std::endl;
    }
    catch (const json::type_error& e)
    {
        std::cout << e.what() << std::endl;
    }

    std::cout << "string with replaced invalid characters: "
              << j_invalid.dump(-1, ' ', false, json::error_handler_t::replace)
              << "\nstring with ignored invalid characters: "
              << j_invalid.dump(-1, ' ', false, json::error_handler_t::ignore)
              << '\n';

    // the invalid byte is kept; print the result byte-wise to make it visible
    std::cout << "string with kept invalid characters:";
    for (const unsigned char c : j_invalid.dump(-1, ' ', false, json::error_handler_t::keep))
    {
        std::cout << ' ' << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    std::cout << '\n';
}
