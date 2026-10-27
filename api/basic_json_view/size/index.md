# nlohmann::basic_json_view::size

```
size_type size() const noexcept;
```

Returns the number of elements, as [`BasicJsonType::size()`](https://json.nlohmann.me/api/basic_json/size/index.md) would for the same value.

## Return value

The return value depends on the type and is defined as follows:

| Value type | return value              |
| ---------- | ------------------------- |
| null       | `0`                       |
| discarded  | `0`                       |
| boolean    | `1`                       |
| string     | `1`                       |
| number     | `1`                       |
| object     | number of key/value pairs |
| array      | number of elements        |

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant: for an object or array, the element count is stored in the index, not counted on demand.

## Notes

As for [`BasicJsonType::size()`](https://json.nlohmann.me/api/basic_json/size/index.md), this does not return the length of a string value — it is `1` for a string, regardless of its length.

If the source text has an object with a duplicate key, every occurrence counts towards its `size()` — unlike [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) (and [`BasicJsonType::parse()`](https://json.nlohmann.me/api/basic_json/parse/index.md)), which keeps only the last value for a repeated key. This means `v.size()` can be larger than `v.materialize().size()`. See the [Notes on duplicate keys](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/#notes) of `operator[]` for why lookups and iteration disagree on how many members there are.

## Examples

Example

The example below uses `size()` and [`empty()`](https://json.nlohmann.me/api/basic_json_view/empty/index.md) to decide whether a parsed message is worth acting on, without materializing it into a `BasicJsonType` value.

```
#include <iostream>
#include <nlohmann/json_view.hpp>

using nlohmann::json_document;

int main()
{
    std::cout << std::boolalpha;

    // decide whether a batch is worth processing before building any
    // nlohmann::json value for it
    json_document batch = json_document::parse(R"([1, 2, 3, 4, 5])");
    json_document empty_batch = json_document::parse("[]");

    std::cout << batch.root().empty() << ' ' << batch.root().size() << '\n';
    std::cout << empty_batch.root().empty() << ' ' << empty_batch.root().size() << '\n';

    // as for basic_json: null has size 0, every other scalar has size 1
    json_document n = json_document::parse("null");
    json_document s = json_document::parse(R"("hi")");
    std::cout << n.root().size() << ' ' << s.root().size() << '\n';
}
```

Output:

```
false 5
true 0
0 1
```

## See also

- [`empty`](https://json.nlohmann.me/api/basic_json_view/empty/index.md) - return whether the value has no elements
- [`BasicJsonType::size`](https://json.nlohmann.me/api/basic_json/size/index.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0 unreleased.
