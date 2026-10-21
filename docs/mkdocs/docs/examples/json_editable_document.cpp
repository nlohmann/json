#include <iostream>
#include <nlohmann/json_view.hpp>

using json = nlohmann::json;
using json_editable_document = nlohmann::json_editable_document;
using json_editable_view = nlohmann::json_editable_view;

int main()
{
    // a configuration file, as it might be read from disk
    const std::string text = R"({"name": "cache", "host": "db1", "port": 6379, "price": 19.90})";
    std::cout << text << "\n\n";

    // patch two fields -- "price" is never touched
    json_editable_document doc = json_editable_document::parse(text);
    doc.set(doc.root(), "host", "db2");
    doc.set(doc.root(), "retries", 3);

    // member order (the new member at the end) and the untouched number's
    // exact spelling survive
    std::cout << doc.root().dump(-1, ' ', false, json_editable_view::number_format::source) << '\n';

    // the same patch on a plain json value: keys are sorted (object_t is a
    // std::map), and "price" is rewritten even though the patch never
    // touched it
    json plain = json::parse(text);
    plain["host"] = "db2";
    plain["retries"] = 3;
    std::cout << plain.dump() << '\n';
}
