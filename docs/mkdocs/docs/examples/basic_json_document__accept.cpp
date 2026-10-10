#include <iostream>
#include <nlohmann/json.hpp>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    std::cout << std::boolalpha;

    // accept() behaves exactly like basic_json::accept(): the same inputs are
    // accepted or rejected, with the same ignore_comments/ignore_trailing_commas
    // options
    std::cout << json_document::accept(R"({"a": 1})") << '\n';
    std::cout << json_document::accept(R"({"a": 1,})") << '\n'; // trailing comma: rejected by default
    std::cout << json_document::accept(R"({"a": 1,})", false, true) << '\n'; // ignore_trailing_commas

    std::cout << (json_document::accept(R"({"a": 1})") == nlohmann::json::accept(R"({"a": 1})")) << '\n';
}
