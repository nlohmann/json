# nlohmann::json_pointer::front

```
const string_t& front() const;
```

Return the first reference token.

## Return value

First reference token.

## Exceptions

Throws [out_of_range.405](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range405) if the JSON pointer has no parent.

## Complexity

Constant.

## Examples

Example

The example shows the usage of `front`.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // different JSON Pointers
    json::json_pointer ptr1("/foo");
    json::json_pointer ptr2("/foo/0");

    // call empty()
    std::cout << "first reference token of \"" << ptr1 << "\" is \"" << ptr1.front() << "\"\n"
              << "first reference token of \"" << ptr2 << "\" is \"" << ptr2.front() << "\"" << std::endl;
}
```

Output:

```
first reference token of "/foo" is "foo"
first reference token of "/foo/0" is "foo"
```

## Version history

- Added in version 3.13.0.
