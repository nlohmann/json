# nlohmann::basic_json::patch_inplace

```
void patch_inplace(const basic_json& json_patch);
```

[JSON Patch](http://jsonpatch.com) defines a JSON document structure for expressing a sequence of operations to apply to a JSON document. With this function, a JSON Patch is applied to the current JSON value by executing all operations from the patch. This function applies a JSON patch in place and returns void.

## Parameters

`json_patch` (in) : JSON patch document

## Exception safety

No guarantees, value may be corrupted by an unsuccessful patch operation.

## Exceptions

- Throws [`parse_error.104`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error104) if the JSON patch does not consist of an array of objects.
- Throws [`parse_error.105`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error105) if the JSON patch is malformed (e.g., mandatory attributes are missing); example: `"operation add must have member path"`.
- Throws [`out_of_range.401`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range401) if an array index is out of range.
- Throws [`out_of_range.403`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range403) if a JSON pointer inside the patch could not be resolved successfully in the current JSON value; example: `"key baz not found"`.
- Throws [`out_of_range.405`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range405) if JSON pointer has no parent ("add", "remove", "move")
- Throws [`out_of_range.411`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range411) if an "add" operation's target location has a parent that is neither an object nor an array.
- Throws [`other_error.501`](https://json.nlohmann.me/home/exceptions/#jsonexceptionother_error501) if "test" operation was unsuccessful.

## Complexity

Linear in the size of the JSON value and the length of the JSON patch. As usually the patch affects only a fraction of the JSON value, the complexity can usually be neglected.

## Notes

Unlike [`patch`](https://json.nlohmann.me/api/basic_json/patch/index.md), `patch_inplace` applies the operation "in place" and no copy of the JSON value is created. That makes it faster for large documents by avoiding the copy. However, the JSON value might be corrupted if the function throws an exception.

## Examples

Example

The following code shows how a JSON patch is applied to a value.

```
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
```

Output:

```
Before
{
    "baz": "qux",
    "foo": "bar"
}

After
{
    "baz": "boo",
    "hello": [
        "world"
    ]
}
```

## See also

- [RFC 6902 (JSON Patch)](https://tools.ietf.org/html/rfc6902)
- [RFC 6901 (JSON Pointer)](https://tools.ietf.org/html/rfc6901)
- [patch](https://json.nlohmann.me/api/basic_json/patch/index.md) applies a JSON Patch
- [merge_patch](https://json.nlohmann.me/api/basic_json/merge_patch/index.md) applies a JSON Merge Patch

## Version history

- Added in version 3.11.0.
- Added [`out_of_range.411`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range411) and stopped relying on an internal assertion when an "add" operation's target location has a non-object/non-array parent in version 3.13.0.
