#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;
using ordered_json_document = nlohmann::ordered_json_document;
using json = nlohmann::json;

int main()
{
    // assert, as a test would, that a received document differs from an
    // unwanted shape -- without ever materializing it into a json value just
    // to compare
    const json_document received = json_document::parse(
                                       R"({"status": "ok", "code": 200})");
    const json unwanted = {{"status", "error"}, {"code", 500}};
    std::cout << std::boolalpha << (received.root() != unwanted) << '\n';

    // json (std::map) compares object members regardless of order ...
    const json_document a = json_document::parse(R"({"a": 1, "b": 2})");
    const json_document b = json_document::parse(R"({"b": 2, "a": 1})");
    std::cout << (a.root() != b.root()) << '\n';

    // ... but ordered_json (ordered_map) compares them in the order they
    // appear, so the very same reordering is detected as a difference
    const ordered_json_document oa = ordered_json_document::parse(R"({"a": 1, "b": 2})");
    const ordered_json_document ob = ordered_json_document::parse(R"({"b": 2, "a": 1})");
    std::cout << (oa.root() != ob.root()) << '\n';
}
