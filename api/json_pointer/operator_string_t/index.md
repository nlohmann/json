# nlohmann::json_pointer::operator string_t

```
operator string_t() const
```

Return a string representation of the JSON pointer.

## Return value

A string representation of the JSON pointer

## Possible implementation

```
operator string_t() const
{
    return to_string();
}
```

## Notes

Deprecation

This function is deprecated in favor of [`to_string`](https://json.nlohmann.me/api/json_pointer/to_string/index.md) and will be removed in a future major version release.

## Examples

Example

The example shows how JSON Pointers can be implicitly converted to strings.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // different JSON Pointers
    json::json_pointer ptr1("/foo/0");
    json::json_pointer ptr2("/a~1b");

    // implicit conversion to string
    std::string s;
    s += ptr1;
    s += "\n";
    s += ptr2;

    std::cout << s << std::endl;
}
```

Output:

```
/foo/0
/a~1b
```

## See also

- [string_t](https://json.nlohmann.me/api/basic_json/string_t/index.md)- type for strings

## Version history

- Since version 2.0.0.
- Changed type to `string_t` and deprecated in version 3.11.0.
