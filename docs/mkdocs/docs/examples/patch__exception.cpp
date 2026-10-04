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
          "a": { "b": 1 }
        }
    )"_json;

    // a patch that tries to move "/a" into one of its own children
    json patch = R"(
        [
          { "op": "move", "from": "/a", "path": "/a/b" }
        ]
    )"_json;

    // exception out_of_range.414
    try
    {
        json patched_doc = doc.patch(patch);
    }
    catch (const json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }

    // the original document is unchanged
    std::cout << std::setw(4) << doc << std::endl;
}
