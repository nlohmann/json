#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;
using json_view = nlohmann::json_view;
using json_pointer = nlohmann::json::json_pointer;

int main()
{
    json_document doc = json_document::parse(R"({"server": {"host": "localhost", "limits": {"connections": 100}}})");
    const json_view config = doc.root();

    // a nested, optional setting read with a default -- no exception, even
    // though "timeout" is missing several levels down
    std::cout << config.value(json_pointer("/server/limits/connections"), 10) << '\n';
    std::cout << config.value(json_pointer("/server/limits/timeout"), 30) << '\n';

    // an out-of-range array index also falls back to the default
    json_document list_doc = json_document::parse(R"({"servers": ["a", "b"]})");
    std::cout << list_doc.root().value(json_pointer("/servers/5"), std::string("none")) << '\n';
}
