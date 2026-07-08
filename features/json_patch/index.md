# JSON Patch and Diff

## Patches

JSON Patch ([RFC 6902](https://tools.ietf.org/html/rfc6902)) defines a JSON document structure for expressing a sequence of operations to apply to a JSON document. With the `patch` function, a JSON Patch is applied to the current JSON value by executing all operations from the patch.

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

## Diff

The library can also calculate a JSON patch (i.e., a **diff**) given two JSON values.

Invariant

For two JSON values *source* and *target*, the following code yields always true:

```
source.patch(diff(source, target)) == target;
```

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
