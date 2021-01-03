#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // tagged byte string
    std::vector<std::uint8_t> vec = {{0xd8, 0x42, 0x44, 0xcA, 0xfe, 0xba, 0xbe}};

    // cbor_tag_handler_t::error throws
    try
    {
        auto b_throw_on_tag = json::from_cbor(vec, true, true, json::cbor_tag_handler_t::error);
    }
    catch (const json::parse_error& e)
    {
        std::cout << e.what() << std::endl;
    }

    // cbor_tag_handler_t::ignore ignores the tag
    auto b_ignore_tag = json::from_cbor(vec, true, true, json::cbor_tag_handler_t::ignore);
    std::cout << b_ignore_tag << std::endl;

    // cbor_tag_handler_t::store stores the tag as binary subtype
    auto b_store_tag = json::from_cbor(vec, true, true, json::cbor_tag_handler_t::store);
    std::cout << b_store_tag << std::endl;
}
