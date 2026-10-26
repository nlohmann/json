# nlohmann::basic_json_view::cend

```
iterator cend() const noexcept;
```

Returns an iterator to one past the last element, in [document order](https://json.nlohmann.me/api/basic_json_view/begin/index.md). Equivalent to [`end()`](https://json.nlohmann.me/api/basic_json_view/end/index.md): a view is always read-only, so `const_iterator` and `iterator` are the same type, and `cend()` exists only so that generic code that expects a `cbegin()`/`cend()` pair works with a view too.

## Return value

Iterator one past the last element; identical to what [`end()`](https://json.nlohmann.me/api/basic_json_view/end/index.md) returns.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Examples

Example

The example below checks that every record of a batch is an object with `std::all_of`, using [`cbegin()`](https://json.nlohmann.me/api/basic_json_view/cbegin/index.md)/`cend()` as the range -- the same way it would for any standard container -- before materializing any record of the batch.

```
#include <algorithm>
#include <iostream>
#include <nlohmann/json_view.hpp>

using nlohmann::json_document;
using nlohmann::json_view;

int main()
{
    // check that every element of a (possibly large) batch is an object,
    // before materializing any of them -- cbegin()/cend() (identical to
    // begin()/end() here) work as the range for std::all_of like they would
    // for any standard container
    json_document batch = json_document::parse(R"([{"id": 1}, {"id": 2}, {"id": 3}])");
    const auto records = batch.root();

    const bool all_objects = std::all_of(records.cbegin(), records.cend(),
                                         [](const json_view & v)
    {
        return v.is_object();
    });

    std::cout << std::boolalpha << all_objects << '\n';
}
```

Output:

```
true
```

## See also

- [end](https://json.nlohmann.me/api/basic_json_view/end/index.md) - returns an iterator to one past the last element
- [cbegin](https://json.nlohmann.me/api/basic_json_view/cbegin/index.md) - returns a const iterator to the first element
- [`BasicJsonType::cend`](https://json.nlohmann.me/api/basic_json/cend/index.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0 unreleased.
