# nlohmann::basic_json::diff

```
static basic_json diff(const basic_json& source,
                       const basic_json& target,
                       const string_t& path = "");
```

Creates a [JSON Patch](http://jsonpatch.com) so that value `source` can be changed into the value `target` by calling [`patch`](https://json.nlohmann.me/api/basic_json/patch/index.md) function.

For two JSON values `source` and `target`, the following code yields `true`:

```
source.patch(diff(source, target)) == target;
```

The equality holds up to [`operator==`](https://json.nlohmann.me/api/basic_json/operator_eq/index.md), so it has the following exceptions:

- A value that is not equal to itself cannot round-trip. This applies to `NaN` (also nested in an array or object) and to [discarded](https://json.nlohmann.me/api/basic_json/is_discarded/index.md) values: `diff` emits a `replace` operation for them. A `NaN` in the patch is serialized as `null`, so a patch that was dumped and parsed again would set `null`.
- Numbers that compare equal produce no operation, even if their types or signs differ: `diff(1, 1.0)`, `diff(1u, 1)` (unsigned and signed integer) and `diff(0.0, -0.0)` all return `[]`. The patched value is then the `source` and keeps its number type.

## Parameters

`source` (in) : JSON value to compare from

`target` (in) : JSON value to compare against

`path` (in) : a prefix that is put verbatim in front of the `path` member of every operation (default: `""`, which addresses the root of the value). The prefix is neither escaped nor validated: `diff(1, 2, "abc")` yields an operation with the `path` `abc`, which is not a valid JSON Pointer. Use it with a valid JSON Pointer such as `/root` and escape `~` and `/` in its reference tokens (see [JSON Pointer](https://json.nlohmann.me/features/json_pointer/index.md)).

## Return value

a JSON patch to convert the `source` to `target`

## Exception safety

Strong guarantee: `source` and `target` are never modified.

## Complexity

Linear in the total number of values (including nested ones) in `source` and `target`, times the cost of a key-based object operation (looking up a key in an object): logarithmic for [`json`](https://json.nlohmann.me/api/json/index.md), and linear for [`ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md) (see [`ordered_map` complexity](https://json.nlohmann.me/api/ordered_map/#complexity)). For `ordered_json`, diffing two objects with `n` and `m` members therefore takes O((n+m)²) when their keys do not line up (e.g., a key was added or the keys are in a different order). The size of the patch is proportional to the number of operations times the length of their paths, so a small change deep inside a value yields a long `path`.

## Notes

- Currently, only `remove`, `add`, and `replace` operations are generated.
- The patch is correct, but not guaranteed to be minimal. For instance, `diff([1,2,3], [0,1,2,3])` yields three `replace` operations and one `add` operation instead of a single insertion.
- Differences between two arrays are reported index by index. Elements that were added at the end of the array are added with `add` operations on the path `/-` (appended in order), and elements that were removed are removed with `remove` operations from the highest index down to the lowest, so that the remaining indices stay valid.
- For objects, the operations for the members of `source` come first (`replace`, `remove`, or the operations for nested values, in the iteration order of `source`), followed by `add` operations for the members that only `target` has.
- For [`ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md), objects with the same keys in a different order are different. As a patch cannot reorder members, `diff` removes all keys of the `source` object and adds them again in the order of the `target`.
- If `source` and `target` differ as a whole (e.g., different types), the patch consists of a single `replace` operation for the root of the value, i.e., with the `path` `""` (or the given `path` prefix).
- The `value` members of the patch hold copies of values of `target`. A [binary](https://json.nlohmann.me/features/binary_values/index.md) value has no JSON representation: when a patch that contains one is serialized, it becomes an object such as `{"bytes":[1,3],"subtype":null}`, so a parsed patch no longer holds a binary value (and would set that object instead).

## Examples

Example

The following code shows how a JSON patch is created as a diff for two JSON values.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using nlohmann::json;
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
              << std::setw(4) << patched_source << '\n';
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

- [RFC 6902 (JSON Patch)](https://tools.ietf.org/html/rfc6902) - specification of JSON Patch
- [`patch`](https://json.nlohmann.me/api/basic_json/patch/index.md) - applies a JSON Patch
- [`patch_inplace`](https://json.nlohmann.me/api/basic_json/patch_inplace/index.md) - applies a JSON Patch in place
- [`merge_patch`](https://json.nlohmann.me/api/basic_json/merge_patch/index.md) - applies a JSON Merge Patch
- [`merge_diff`](https://json.nlohmann.me/api/basic_json/merge_diff/index.md) - creates a diff as a JSON Merge Patch
- [JSON Patch and Diff](https://json.nlohmann.me/features/json_patch/index.md) - the article on JSON Patch

## Version history

- Added in version 2.0.0.
