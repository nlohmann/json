# nlohmann::basic_json::diff

```
static basic_json diff(const basic_json& source,
                       const basic_json& target);
```

Creates a [JSON Patch](http://jsonpatch.com) so that value `source` can be changed into the value `target` by calling [`patch`](https://json.nlohmann.me/api/basic_json/patch/index.md) function.

For two JSON values `source` and `target`, the following code yields always `true`:

```
source.patch(diff(source, target)) == target;
```

## Parameters

`source` (in) : JSON value to compare from

`target` (in) : JSON value to compare against

## Return value

a JSON patch to convert the `source` to `target`

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Complexity

Linear in the lengths of `source` and `target`.

## Notes

Currently, only `remove`, `add`, and `replace` operations are generated.

## Examples

Example

The following code shows how a JSON patch is created as a diff for two JSON values.

```
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
            "baz": "qux",
            "foo": "bar"
        }
    )"_json;

    // the target document
    json target = R"(
        {
            "baz": "boo",
            "hello": [
                "world"
            ]
        }
    )"_json;

    // create the patch
    json patch = json::diff(source, target);

    // roundtrip
    json patched_source = source.patch(patch);

    // output patch and roundtrip result
    std::cout << std::setw(4) << patch << "\n\n"
              << std::setw(4) << patched_source << std::endl;
}
```

Output:

```
[
    {
        "op": "replace",
        "path": "/baz",
        "value": "boo"
    },
    {
        "op": "remove",
        "path": "/foo"
    },
    {
        "op": "add",
        "path": "/hello",
        "value": [
            "world"
        ]
    }
]

{
    "baz": "boo",
    "hello": [
        "world"
    ]
}
```

## See also

- [RFC 6902 (JSON Patch)](https://tools.ietf.org/html/rfc6902)
- [patch](https://json.nlohmann.me/api/basic_json/patch/index.md) applies a JSON Patch
- [patch_inplace](https://json.nlohmann.me/api/basic_json/patch_inplace/index.md) applies a JSON Patch in place
- [merge_patch](https://json.nlohmann.me/api/basic_json/merge_patch/index.md) applies a JSON Merge Patch

## Version history

- Added in version 2.0.0.
