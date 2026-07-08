# nlohmann::basic_json::merge_patch

```
void merge_patch(const basic_json& apply_patch);
```

The merge patch format is primarily intended for use with the HTTP PATCH method as a means of describing a set of modifications to a target resource's content. This function applies a merge patch to the current JSON value.

The function implements the following algorithm from Section 2 of [RFC 7396 (JSON Merge Patch)](https://tools.ietf.org/html/rfc7396):

```
define MergePatch(Target, Patch):
  if Patch is an Object:
    if Target is not an Object:
      Target = {} // Ignore the contents and set it to an empty Object
    for each Name/Value pair in Patch:
      if Value is null:
        if Name exists in Target:
          remove the Name/Value pair from Target
      else:
        Target[Name] = MergePatch(Target[Name], Value)
    return Target
  else:
    return Patch
```

Thereby, `Target` is the current object; that is, the patch is applied to the current value.

## Parameters

`apply_patch` (in) : the patch to apply

## Complexity

Linear in the lengths of `apply_patch`.

## Examples

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

## See also

- [RFC 7396 (JSON Merge Patch)](https://tools.ietf.org/html/rfc7396)
- [patch](https://json.nlohmann.me/api/basic_json/patch/index.md) apply a JSON patch

## Version history

- Added in version 3.0.0.
