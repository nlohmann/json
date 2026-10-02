#include <iostream>
#include <nlohmann/json_view.hpp>
#include <string>

using json_document = nlohmann::json_document;
using json_view = nlohmann::json_view;

int main()
{
    json_document doc = json_document::parse(R"({"server": {"host": "localhost"}})");
    const json_view server = doc.root()["server"];

    // "port" is missing -- value() returns the default instead of
    // throwing, so optional configuration fields never need their own
    // try/catch
    std::cout << server.value("host", std::string("0.0.0.0")) << '\n';
    std::cout << server.value("port", 8080) << '\n';

    // a present but wrong-typed default still throws -- value() only
    // replaces "not found", not "wrong type", exactly as basic_json::value
    try
    {
        static_cast<void>(server.value("host", 0));
    }
    catch (const nlohmann::json::type_error& e)
    {
        std::cout << e.what() << '\n';
    }
}
