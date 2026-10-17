#include <iostream>
#include <string>
#include <nlohmann/json.hpp>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    std::cout << std::boolalpha;

    // an lvalue std::string is BORROWED: the document only stores a pointer
    // into `text`, so `text` must outlive `borrowed`
    std::string text = R"({"count": 3})";
    json_document borrowed = json_document::parse(text);
    std::cout << borrowed.owns_source() << '\n'; // false

    // an rvalue std::string is MOVED into the document -- no copy of the text
    json_document owned = json_document::parse(std::string(R"({"count": 3})"));
    std::cout << owned.owns_source() << '\n'; // true

    // errors are identical to basic_json::parse: same exception id, message,
    // and position, because the library parser runs on the same bytes on a
    // failing input
    try
    {
        static_cast<void>(json_document::parse(R"({"count": )"));
    }
    catch (const nlohmann::json::parse_error& e)
    {
        std::cout << e.id << '\n';
    }
}
