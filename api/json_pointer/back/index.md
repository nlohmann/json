# nlohmann::json_pointer::back

```
const string_t& back() const;
```

Return the last reference token.

## Return value

Last reference token.

## Exceptions

Throws [out_of_range.405](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range405) if the JSON pointer has no parent.

## Complexity

Constant.

## Examples

Example

The example shows the usage of `back`.

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
    std::cout << "last reference token of \"" << ptr1 << "\" is \"" << ptr1.back() << "\"\n"
              << "last reference token of \"" << ptr2 << "\" is \"" << ptr2.back() << "\"" << std::endl;
}
```

Output:

```
last reference token of "/foo" is "foo"
last reference token of "/foo/0" is "0"
```

## Version history

- Added in version 3.6.0.
- Changed return type to `string_t` in version 3.11.0.
