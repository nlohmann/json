#include <iostream>
#include <nlohmann/json_view.hpp>

using json = nlohmann::json;
using json_editable_document = nlohmann::json_editable_document;
using json_editable_view = nlohmann::json_editable_view;

int main()
{
    // a configuration file, as it might be read from disk -- "price" is
    // written with a trailing zero that has no effect on its value
    const std::string text = R"({
  "name": "cache",
  "host": "db1",
  "port": 6379,
  "price": 19.90,
  "replicas": ["db2", "db3"],
  "timeout": 30
})";

    json_editable_document doc = json_editable_document::parse(text);

    doc.set(doc.root()["port"], 6380);                    // (1) replace a value
    doc.set(doc.root(), "region", "us-east");              // (2) add a member
    doc.set(doc.root()["replicas"], 0, "db4");             // (3) assign an element
    doc.set(json::json_pointer("/timeout"), 45);           // (4) via a JSON pointer

    // members stay in document order (the new one at the end), and a number
    // that was not itself edited keeps its exact spelling
    std::cout << doc.root().dump(2, ' ', false, json_editable_view::number_format::source) << "\n\n";

    // the same edits on a plain json value: object_t is a std::map, so
    // parsing already sorted the keys, and dump() rewrites every number to
    // its shortest form, even "price", which was never touched
    json plain = json::parse(text);
    plain["port"] = 6380;
    plain["region"] = "us-east";
    plain["replicas"][0] = "db4";
    plain[json::json_pointer("/timeout")] = 45;
    std::cout << plain.dump(2) << '\n';
}
