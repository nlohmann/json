#include <iostream>
#include <utility>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    std::cout << std::boolalpha;

    // the default constructor creates an empty (discarded) document
    json_document empty;
    std::cout << empty.is_discarded() << '\n';

    // json_document is move-only: parse() itself returns by value (moved out),
    // and a document can be moved again, e.g. into a container
    json_document doc = json_document::parse(R"({"a": 1})");
    json_document moved = std::move(doc);
    std::cout << moved.root().is_object() << '\n';

    // copying is disabled at compile time:
    // json_document another = moved; // does not compile
}
