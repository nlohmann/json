# nlohmann::basic_json_view::cbegin

```
iterator cbegin() const noexcept;
```

Returns an iterator to the first element, in [document order](https://json.nlohmann.me/api/basic_json_view/begin/index.md). Equivalent to [`begin()`](https://json.nlohmann.me/api/basic_json_view/begin/index.md): a view is always read-only, so `const_iterator` and `iterator` are the same type, and `cbegin()` exists only so that generic code that expects a `cbegin()`/`cend()` pair works with a view too.

## Return value

Iterator to the first element; identical to what [`begin()`](https://json.nlohmann.me/api/basic_json_view/begin/index.md) returns.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Examples

Example

The example below sums many measurements with `std::accumulate`, using `cbegin()`/[`cend()`](https://json.nlohmann.me/api/basic_json_view/cend/index.md) as the range — the same way it would for any standard container — without ever materializing the whole array into a `BasicJsonType` value.

```
#include <iostream>
#include <numeric>
#include <nlohmann/json_view.hpp>

using nlohmann::json_document;
using nlohmann::json_view;

int main()
{
    // sum many measurements with std::accumulate; cbegin()/cend() (identical
    // to begin()/end() here -- the view is always read-only) let the view be
    // used with standard algorithms without ever materializing the whole
    // array into a nlohmann::json value
    json_document measurements = json_document::parse("[3, 1, 4, 1, 5, 9, 2, 6]");
    const auto values = measurements.root();

    const int sum = std::accumulate(values.cbegin(), values.cend(), 0,
                                    [](int total, const json_view & v)
    {
        return total + v.materialize().get<int>();
    });

    std::cout << sum << '\n';
}
```

Output:

```
31
```

## See also

- [`begin`](https://json.nlohmann.me/api/basic_json_view/begin/index.md) - returns an iterator to the first element
- [`cend`](https://json.nlohmann.me/api/basic_json_view/cend/index.md) - returns a const iterator to one past the last element
- [`BasicJsonType::cbegin`](https://json.nlohmann.me/api/basic_json/cbegin/index.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0 unreleased.
