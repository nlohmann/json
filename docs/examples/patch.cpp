#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

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

    // apply the patch
    json patched_doc = doc.patch(patch);

    // output original and patched document
    std::cout << std::setw(4) << doc << "\n\n"
              << std::setw(4) << patched_doc << std::endl;
}
