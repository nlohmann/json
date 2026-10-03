# nlohmann::basic_json::cbegin

```
const_iterator cbegin() const noexcept;
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

The following code shows an example for `cbegin()`.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create an array value
    const json array = {1, 2, 3, 4, 5};

    // get an iterator to the first element
    json::const_iterator it = array.cbegin();

    // serialize the element that the iterator points to
    std::cout << *it << '\n';
}
```

Output:

```
1
```

## See also

- [begin](https://json.nlohmann.me/api/basic_json/begin/index.md) returns an iterator to the first element
- [cend](https://json.nlohmann.me/api/basic_json/cend/index.md) returns a const iterator to one past the last element
- [crbegin](https://json.nlohmann.me/api/basic_json/crbegin/index.md) returns a const reverse iterator to the last element
- [Iterators](https://json.nlohmann.me/features/iterators/index.md) - the article on iterators

## Version history

- Added in version 1.0.0.
