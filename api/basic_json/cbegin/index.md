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

## Version history

- Added in version 1.0.0.
