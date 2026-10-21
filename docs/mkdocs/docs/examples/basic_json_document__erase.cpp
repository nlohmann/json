#include <iostream>
#include <nlohmann/json_view.hpp>

using json = nlohmann::json;
using json_editable_document = nlohmann::json_editable_document;
using json_editable_view = nlohmann::json_editable_view;

int main()
{
    // a deprecated field is dropped from a configuration file, and a
    // decommissioned replica is removed from the list -- "price" keeps its
    // trailing zero, and the fields around the removed ones keep their order
    const std::string text = R"({
  "name": "cache",
  "legacy_host": "db0",
  "host": "db1",
  "price": 19.90,
  "replicas": ["db2", "db3", "db4"]
})";

    json_editable_document doc = json_editable_document::parse(text);

    doc.erase(doc.root(), "legacy_host");                                      // (1) an object member
    doc.erase(doc.root()["replicas"], 1);                                      // (2) an array element ("db3")
    const std::size_t removed = doc.erase(json::json_pointer("/replicas/0"));  // (3) via a JSON pointer

    std::cout << removed << '\n';
    std::cout << doc.root().dump(2, ' ', false, json_editable_view::number_format::source) << "\n\n";

    // the same edits on a plain json value: object_t is a std::map, so
    // parsing already sorted the keys, and dump() rewrites every number to
    // its shortest form, even "price", which was never touched
    json plain = json::parse(text);
    plain.erase("legacy_host");
    plain["replicas"].erase(1);
    plain["replicas"].erase(0);
    std::cout << plain.dump(2) << '\n';
}
