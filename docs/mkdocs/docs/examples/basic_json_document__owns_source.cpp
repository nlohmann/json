#include <iostream>
#include <string>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    std::cout << std::boolalpha;

    std::string text = R"({"a": 1})";

    // borrowed: the document only points into `text`; `text` must outlive it
    json_document borrowed = json_document::parse(text);
    std::cout << borrowed.owns_source() << '\n';

    // owned: parse_copy() always takes its own copy
    json_document copied = json_document::parse_copy(text);
    std::cout << copied.owns_source() << '\n';

    // owned: an rvalue std::string is moved in, not copied, but still owned
    json_document moved_in = json_document::parse(std::string(text));
    std::cout << moved_in.owns_source() << '\n';
}
