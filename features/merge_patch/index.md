# JSON Merge Patch

The library supports JSON Merge Patch ([RFC 7386](https://tools.ietf.org/html/rfc7386)) as a patch format. The merge patch format is primarily intended for use with the HTTP PATCH method as a means of describing a set of modifications to a target resource's content. This function applies a merge patch to the current JSON value.

Instead of using [JSON Pointer](https://json.nlohmann.me/features/json_pointer/index.md) to specify values to be manipulated, it describes the changes using a syntax that closely mimics the document being modified.

Example

The following code shows how a JSON Merge Patch is applied to a JSON document.

```
#include <iostream>
#include <nlohmann/json.hpp>
#include <iomanip> // for std::setw

using json = nlohmann::json;
using namespace nlohmann::literals;

int main()
{
    // the original document
    json document = R"({
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
            })"_json;

    // the patch
    json patch = R"({
                "title": "Hello!",
                "phoneNumber": "+01-123-456-7890",
                "author": {
                    "familyName": null
                },
                "tags": [
                    "example"
                ]
            })"_json;

    // apply the patch
    document.merge_patch(patch);

    // output original and patched document
    std::cout << std::setw(4) << document << std::endl;
}
```

Output:

```
{
    "author": {
        "givenName": "John"
    },
    "content": "This will be unchanged",
    "phoneNumber": "+01-123-456-7890",
    "tags": [
        "example"
    ],
    "title": "Hello!"
}
```
