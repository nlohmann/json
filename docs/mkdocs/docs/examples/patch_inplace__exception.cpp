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
          "a": 1,
          "b": 2
        }
    )"_json;

    // a patch whose second operation fails
    json patch = R"(
        [
          { "op": "replace", "path": "/a", "value": 99 },
          { "op": "remove", "path": "/nonexistent" }
        ]
    )"_json;

    // exception out_of_range.403
    try
    {
        doc.patch_inplace(patch);
    }
    catch (const json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }

    // the first operation has already been applied to doc
    std::cout << std::setw(4) << doc << std::endl;
}
