# nlohmann::json_pointer::back

```
const string_t& back() const;
```

Return the last reference token.

## Return value

Last reference token.

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

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

## See also

- [front](https://json.nlohmann.me/api/json_pointer/front/index.md) return first reference token
- [pop_back](https://json.nlohmann.me/api/json_pointer/pop_back/index.md) remove the last reference token
- [push_back](https://json.nlohmann.me/api/json_pointer/push_back/index.md) append an unescaped token at the end of the pointer
- [parent_pointer](https://json.nlohmann.me/api/json_pointer/parent_pointer/index.md) returns the parent of this JSON pointer

## Version history

- Added in version 3.6.0.
- Changed return type to `string_t` in version 3.11.0.
