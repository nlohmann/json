# <small>nlohmann::basic_json_view::</small>cbegin

```cpp
iterator cbegin() const noexcept;
```

Returns an iterator to the first element, in [document order](begin.md). Equivalent to [`begin()`](begin.md): a view
is always read-only, so `#!cpp const_iterator` and `#!cpp iterator` are the same type, and `cbegin()` exists only so
that generic code that expects a `cbegin()`/`cend()` pair works with a view too.

## Return value

Iterator to the first element; identical to what [`begin()`](begin.md) returns.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Examples

??? example

    The example below sums many measurements with `std::accumulate`, using `cbegin()`/[`cend()`](cend.md) as the
    range -- the same way it would for any standard container -- without ever materializing the whole array into a
    `BasicJsonType` value.

    ```cpp
    #include <iostream>
    #include <numeric>
    #include <nlohmann/json_view.hpp>
    
    using json_document = nlohmann::json_document;
    using json_view = nlohmann::json_view;
    
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

    ```json
    31
    
    ```

## See also

- [begin](begin.md) - returns an iterator to the first element
- [cend](cend.md) - returns a const iterator to one past the last element
- [`BasicJsonType::cbegin`](../basic_json/cbegin.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
