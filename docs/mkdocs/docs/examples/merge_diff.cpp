#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace nlohmann::literals;

int main()
{
    // the source document
    json source = R"(
        {
            "title": "Goodbye!",
            "author": {
                "givenName": "John",
                "familyName": "Doe"
            },
            "tags": [
                "example",
                "sample"
            ],
            "content": "This will be unchanged"
        }
    )"_json;

    // the target document
    json target = R"(
        {
            "title": "Hello!",
            "author": {
                "givenName": "John"
            },
            "tags": [
                "example"
            ],
            "content": "This will be unchanged",
            "phoneNumber": "+01-123-456-7890"
        }
    )"_json;

    // create the patch
    json patch = json::merge_diff(source, target);

    // roundtrip
    json patched_source = source;
    patched_source.merge_patch(patch);

    // output patch and roundtrip result
    std::cout << std::setw(4) << patch << "\n\n"
              << std::setw(4) << patched_source << std::endl;
}
