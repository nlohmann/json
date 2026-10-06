#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    // node_count() is the size of the flat index: one 16-byte node per value,
    // plus one per object key (values and keys are all the index stores)
    json_document scalar = json_document::parse("42");
    std::cout << scalar.node_count() << '\n';

    json_document doc = json_document::parse(R"({"a": 1, "b": [1, 2]})");
    std::cout << doc.node_count() << '\n';
}
