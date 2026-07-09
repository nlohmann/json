# nlohmann::basic_json::patch

```
basic_json patch(const basic_json& json_patch) const;
```

[JSON Patch](http://jsonpatch.com) defines a JSON document structure for expressing a sequence of operations to apply to a JSON document. With this function, a JSON Patch is applied to the current JSON value by executing all operations from the patch.

## Parameters

`json_patch` (in) : JSON patch document

## Return value

patched document

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

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

The application of a patch is atomic: Either all operations succeed and the patched document is returned or an exception is thrown. In any case, the original value is not changed: the patch is applied to a copy of the value.

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

    // apply the patch
    json patched_doc = doc.patch(patch);

    // output original and patched document
    std::cout << std::setw(4) << doc << "\n\n"
              << std::setw(4) << patched_doc << std::endl;
}
```

Output:

```
{
    "baz": "qux",
    "foo": "bar"
}

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
- [patch_inplace](https://json.nlohmann.me/api/basic_json/patch_inplace/index.md) applies a JSON Patch without creating a copy of the document
- [merge_patch](https://json.nlohmann.me/api/basic_json/merge_patch/index.md) applies a JSON Merge Patch

## Version history

- Added in version 2.0.0.
- Added [`out_of_range.411`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range411) and stopped relying on an internal assertion when an "add" operation's target location has a non-object/non-array parent in version 3.13.0.
