#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;
using json_pointer = nlohmann::json::json_pointer;

int main()
{
    json_document doc = json_document::parse(R"({"region": "eu", "servers": ["eu-1", "eu-2"]})");
    const auto root = doc.root();

    std::cout << root.at(json_pointer("/servers/1")).materialize().dump() << '\n';

    // at() throws for every resolution failure -- with the very same
    // message json::at(ptr) would throw for the same pointer and the same
    // document
    try
    {
        static_cast<void>(root.at(json_pointer("/servers/5")));
    }
    catch (const nlohmann::json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }

    try
    {
        static_cast<void>(root.at(json_pointer("/missing")));
    }
    catch (const nlohmann::json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }
}
