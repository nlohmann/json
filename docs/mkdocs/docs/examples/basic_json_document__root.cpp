#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    std::cout << std::boolalpha;

    json_document doc = json_document::parse(R"({"greeting": "hi"})");
    std::cout << doc.root().is_object() << '\n';

    // root() is a cheap handle, not a copy: repeated calls observe the same value
    std::cout << (doc.root().type() == doc.root().type()) << '\n';

    // the root of a failed parse (allow_exceptions == false) is discarded
    json_document failed = json_document::parse("{", false);
    std::cout << failed.root().is_discarded() << '\n';
}
