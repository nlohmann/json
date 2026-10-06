#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;
using json_view = nlohmann::json_view;

int main()
{
    // required fields of a service configuration -- at() reports a missing
    // or wrong-typed field with the very same exception basic_json::at()
    // would throw for the equivalent nlohmann::json value, so error
    // handling written against basic_json::at() keeps working unchanged
    json_document config = json_document::parse(R"({"name": "cache", "port": "6379"})");
    const json_view service = config.root();

    std::cout << service.at("port").materialize().dump() << '\n';

    try
    {
        // "port" is a string, not an array
        static_cast<void>(service.at("port").at(0));
    }
    catch (const nlohmann::json::type_error& e)
    {
        std::cout << e.what() << '\n';
    }

    try
    {
        static_cast<void>(service.at("timeout"));
    }
    catch (const nlohmann::json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }
}
