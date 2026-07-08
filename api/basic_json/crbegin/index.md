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

## Version history

- Added in version 1.0.0.
