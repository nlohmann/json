#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;
using json_pointer = nlohmann::json::json_pointer;

int main()
{
    // a larger document; operator[] with a JSON pointer reaches straight to
    // one deeply nested field, without ever building a tree for the rest
    json_document doc = json_document::parse(R"(
      {
        "region": {
          "servers": [
            {"name": "eu-1", "metrics": {"cpu": 0.42}},
            {"name": "eu-2", "metrics": {"cpu": 0.71}}
          ]
        }
      }
    )");

    const auto root = doc.root();
    std::cout << root[json_pointer("/region/servers/1/metrics/cpu")].materialize().dump() << '\n';

    // a missing key or an out-of-range index along the path gives a
    // discarded view, exactly where const json::operator[] would be
    // undefined behavior for the same pointer
    if (const auto missing = root[json_pointer("/region/servers/5/metrics/cpu")])
    {
        std::cout << missing.materialize().dump() << '\n';
    }
    else
    {
        std::cout << "no such server\n";
    }

    // indexing into a primitive still throws, as basic_json::operator[]
    // does for the same pointer
    try
    {
        static_cast<void>(root[json_pointer("/region/servers/0/name/x")]);
    }
    catch (const nlohmann::json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }
}
