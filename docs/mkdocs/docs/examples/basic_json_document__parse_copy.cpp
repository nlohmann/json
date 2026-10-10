#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

json_document parse_from_temporary_buffer()
{
    char buffer[] = R"({"a": 1})";
    // parse() would borrow `buffer`, which is about to go out of scope;
    // parse_copy() takes its own copy instead, so the returned document does
    // not depend on `buffer` afterward
    return json_document::parse_copy(buffer);
}

int main()
{
    std::cout << std::boolalpha;

    json_document doc = parse_from_temporary_buffer();
    std::cout << doc.owns_source() << '\n';
    std::cout << doc.root().is_object() << '\n';
}
