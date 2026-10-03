# nlohmann::basic_json::crbegin

```
const_reverse_iterator crbegin() const noexcept;
```

Returns an iterator to the reverse-beginning; that is, the last element.

## Return value

reverse iterator to the last element

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Examples

Example

The following code shows an example for `crbegin()`.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create an array value
    json array = {1, 2, 3, 4, 5};

    // get an iterator to the reverse-beginning
    json::const_reverse_iterator it = array.crbegin();

    // serialize the element that the iterator points to
    std::cout << *it << '\n';
}
```

Output:

```
5
```

## See also

- [crend](https://json.nlohmann.me/api/basic_json/crend/index.md) returns a const reverse iterator to one before the first element
- [rbegin](https://json.nlohmann.me/api/basic_json/rbegin/index.md) returns a reverse iterator to the last element
- [cbegin](https://json.nlohmann.me/api/basic_json/cbegin/index.md) returns a const iterator to the first element
- [Iterators](https://json.nlohmann.me/features/iterators/index.md) - the article on iterators

## Version history

- Added in version 1.0.0.
