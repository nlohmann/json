# nlohmann::basic_json_view::end

```
iterator end() const noexcept;
```

Returns an iterator to one past the last element of an array, one past the last member value of an object, in **document order** -- see [`begin()`](https://json.nlohmann.me/api/basic_json_view/begin/index.md). A primitive value iterates as a range of one element (itself), and a `null` value or a [discarded](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md) view iterates as an empty range (`begin() == end()`).

## Return value

Iterator one past the last element.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

`iterator` is a forward iterator: unlike `BasicJsonType::iterator`, it cannot be decremented, so there is no way to reach the last element by stepping back from `end()`. Use [`back()`](https://json.nlohmann.me/api/basic_json_view/back/index.md) instead.

## Examples

Example

The example below scans a (possibly large) array of readings for the first one over a threshold, stopping the loop at `end()` as soon as one is found. Only the matching reading, if any, is ever materialized.

```
#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    // scan a (possibly large) array of readings for the first one over a
    // threshold; the loop stops at end() as soon as one is found, and only
    // the matching reading is ever materialized
    json_document readings = json_document::parse("[12, 18, 25, 31, 9]");
    const auto values = readings.root();

    auto it = values.begin();
    for (; it != values.end(); ++it)
    {
        if (it->materialize().get<int>() > 20)
        {
            break;
        }
    }

    if (it != values.end())
    {
        std::cout << "first reading over 20: " << it->materialize().dump() << '\n';
    }
}
```

Output:

```
first reading over 20: 25
```

## See also

- [begin](https://json.nlohmann.me/api/basic_json_view/begin/index.md) - returns an iterator to the first element
- [cend](https://json.nlohmann.me/api/basic_json_view/cend/index.md) - returns a const iterator to one past the last element
- [`BasicJsonType::end`](https://json.nlohmann.me/api/basic_json/end/index.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0 unreleased.
