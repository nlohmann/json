#include <iostream>
#include <nlohmann/json_view.hpp>

using ordered_json_editable_document = nlohmann::ordered_json_editable_document;

int main()
{
    // ordered_json_editable_document is basic_json_document<nlohmann::ordered_json, true>
    ordered_json_editable_document doc = ordered_json_editable_document::parse(R"({"z": 1, "a": 2, "m": 3})");
    doc.set(doc.root(), "b", 4); // set() always appends a new member at the end

    // materialize() preserves the document order (with "b" at the end),
    // instead of sorting the keys the way json_editable_document does
    std::cout << doc.root().materialize().dump() << '\n';
}
