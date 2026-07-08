# nlohmann::basic_json::crend

```
const_reverse_iterator crend() const noexcept;
```

Returns an iterator to the reverse-end; that is, one before the first element. This element acts as a placeholder, attempting to access it results in undefined behavior.

## Return value

reverse iterator to the element following the last element

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Examples

Example

The following code shows an example for `crend()`.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create an array value
    json array = {1, 2, 3, 4, 5};

    // get an iterator to the reverse-end
    json::const_reverse_iterator it = array.crend();

    // increment the iterator to point to the first element
    --it;

    // serialize the element that the iterator points to
    std::cout << *it << '\n';
}
```

Output:

```
1
```

## Version history

- Added in version 1.0.0.
