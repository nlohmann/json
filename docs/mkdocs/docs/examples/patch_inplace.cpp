#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace nlohmann::literals;

int main()
{
    // the original document
    json doc = R"(
        {
          "baz": "qux",
          "foo": "bar"
        }
    )"_json;

    // the patch
    json patch = R"(
        [
          { "op": "replace", "path": "/baz", "value": "boo" },
          { "op": "add", "path": "/hello", "value": ["world"] },
          { "op": "remove", "path": "/foo"}
        ]
    )"_json;

    // output original document
    std::cout << "Before\n" << std::setw(4) << doc << std::endl;

    // apply the patch
    doc.patch_inplace(patch);

    // output patched document
    std::cout << "\nAfter\n" << std::setw(4) << doc << std::endl;
}
