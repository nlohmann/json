#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    std::cout << std::boolalpha;

    // with allow_exceptions == false, a parse error produces a discarded
    // document instead of throwing -- exactly like basic_json::parse()
    json_document doc = json_document::parse(R"({"a": )", /* allow_exceptions */ false);
    std::cout << doc.is_discarded() << '\n';
    std::cout << doc.root().is_discarded() << '\n';

    // a successful parse is never discarded
    json_document ok = json_document::parse(R"({"a": 1})", false);
    std::cout << ok.is_discarded() << '\n';
}
