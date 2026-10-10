#include <iostream>
#include <string>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    std::cout << std::boolalpha;

    std::string text = R"({"a": 1})";
    json_document doc = json_document::parse(text);

    // source() is the parsed text, whether borrowed or owned
    std::cout << (doc.source().size() == text.size()) << '\n';
    std::cout << std::string(doc.source().data(), doc.source().size()) << '\n';

    // for a borrowed document, source() points right into the caller's buffer
    std::cout << (doc.source().data() == text.data()) << '\n';
}
