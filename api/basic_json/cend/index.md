# nlohmann::basic_json::cend

```
const_iterator cend() const noexcept;
```

Returns an iterator to one past the last element.

## Return value

iterator one past the last element

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Examples

Example

The following code shows an example for `cend()`.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create an array value
    json array = {1, 2, 3, 4, 5};

    // get an iterator to one past the last element
    json::const_iterator it = array.cend();

    // decrement the iterator to point to the last element
    --it;

    // serialize the element that the iterator points to
    std::cout << *it << '\n';
}
```

Output:

```
5
```

## See also

- [end](https://json.nlohmann.me/api/basic_json/end/index.md) returns an iterator to one past the last element
- [cbegin](https://json.nlohmann.me/api/basic_json/cbegin/index.md) returns a const iterator to the first element
- [crend](https://json.nlohmann.me/api/basic_json/crend/index.md) returns a const reverse iterator to one before the first element
- [Iterators](https://json.nlohmann.me/features/iterators/index.md) - the article on iterators

## Version history

- Added in version 1.0.0.
