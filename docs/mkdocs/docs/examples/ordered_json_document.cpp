#include <iostream>
#include <nlohmann/json_view.hpp>

using ordered_json_document = nlohmann::ordered_json_document;

int main()
{
    // ordered_json_document is basic_json_document<nlohmann::ordered_json>:
    // materialize() preserves the insertion (source) order of object keys,
    // instead of sorting them like json_document does
    ordered_json_document doc = ordered_json_document::parse(R"({"z": 1, "a": 2, "m": 3})");
    std::cout << doc.root().materialize().dump() << '\n';
}
