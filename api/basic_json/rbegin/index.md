# nlohmann::basic_json::rbegin

```
reverse_iterator rbegin() noexcept;
const_reverse_iterator rbegin() const noexcept;
```

Returns an iterator to the reverse-beginning; that is, the last element.

`rbegin()` points to the last element and `rend()` to the position before the first element. The upper row is the reversed sequence and the lower row the forward sequence; dashed arrows link each reverse iterator to the forward iterator it stores, and dashed cells are past-the-last positions.

## Return value

reverse iterator to the last element

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Examples

Example

The following code shows an example for `rbegin()`.

```
#include <iostream>
#include <nlohmann/json.hpp>

using nlohmann::json;

int main()
{
    // create an array value
    json array = {1, 2, 3, 4, 5};

    // get an iterator to the reverse-beginning
    json::reverse_iterator it = array.rbegin();

    // serialize the element that the iterator points to
    std::cout << *it << '\n';
}
```

Output:

```
5
```

## See also

- [`rend`](https://json.nlohmann.me/api/basic_json/rend/index.md) - returns a reverse iterator to one before the first element
- [`crbegin`](https://json.nlohmann.me/api/basic_json/crbegin/index.md) - returns a const reverse iterator to the last element
- [`begin`](https://json.nlohmann.me/api/basic_json/begin/index.md) - returns an iterator to the first element
- [Iterators](https://json.nlohmann.me/features/iterators/index.md) - the article on iterators

## Version history

- Added in version 1.0.0.
