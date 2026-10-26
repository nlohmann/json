# nlohmann::basic_json_view::empty

```
bool empty() const noexcept;
```

Checks whether [`size()`](https://json.nlohmann.me/api/basic_json_view/size/index.md) is `0`, as [`BasicJsonType::empty()`](https://json.nlohmann.me/api/basic_json/empty/index.md) would for the same value.

## Return value

The return value depends on the type and is defined as follows:

| Value type | return value        |
| ---------- | ------------------- |
| null       | `true`              |
| discarded  | `true`              |
| boolean    | `false`             |
| string     | `false`             |
| number     | `false`             |
| object     | `object_t::empty()` |
| array      | `array_t::empty()`  |

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

As for [`BasicJsonType::empty()`](https://json.nlohmann.me/api/basic_json/empty/index.md), this does not return whether a string value is empty -- it is `false` for any string, regardless of its length.

## Examples

Example

The example below uses [`size()`](https://json.nlohmann.me/api/basic_json_view/size/index.md) and `empty()` to decide whether a parsed message is worth acting on, without materializing it into a `BasicJsonType` value.

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

- [size](https://json.nlohmann.me/api/basic_json_view/size/index.md) - return the number of elements
- [`BasicJsonType::empty`](https://json.nlohmann.me/api/basic_json/empty/index.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0 unreleased.
