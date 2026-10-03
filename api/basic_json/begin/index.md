# nlohmann::basic_json::begin

```
iterator begin() noexcept;
const_iterator begin() const noexcept;
```

Returns an iterator to the first element.

## Return value

iterator to the first element

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Examples

Example

The following code shows an example for `begin()`.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create an array value
    json array = {1, 2, 3, 4, 5};

    // get an iterator to the first element
    json::iterator it = array.begin();

    // serialize the element that the iterator points to
    std::cout << *it << '\n';
}
```

Output:

```
1
```

## See also

- [end](https://json.nlohmann.me/api/basic_json/end/index.md) returns an iterator to one past the last element
- [cbegin](https://json.nlohmann.me/api/basic_json/cbegin/index.md) returns a const iterator to the first element
- [rbegin](https://json.nlohmann.me/api/basic_json/rbegin/index.md) returns a reverse iterator to the last element
- [items](https://json.nlohmann.me/api/basic_json/items/index.md) returns an iteration proxy to access keys and values during range-based for loops
- [Iterators](https://json.nlohmann.me/features/iterators/index.md) - the article on iterators

## Version history

- Added in version 1.0.0.
