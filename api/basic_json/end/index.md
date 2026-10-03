# nlohmann::basic_json::end

```
iterator end() noexcept;
const_iterator end() const noexcept;
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

The following code shows an example for `end()`.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create an array value
    json array = {1, 2, 3, 4, 5};

    // get an iterator to one past the last element
    json::iterator it = array.end();

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

- [begin](https://json.nlohmann.me/api/basic_json/begin/index.md) returns an iterator to the first element
- [cend](https://json.nlohmann.me/api/basic_json/cend/index.md) returns a const iterator to one past the last element
- [rend](https://json.nlohmann.me/api/basic_json/rend/index.md) returns a reverse iterator to one before the first element
- [Iterators](https://json.nlohmann.me/features/iterators/index.md) - the article on iterators

## Version history

- Added in version 1.0.0.
