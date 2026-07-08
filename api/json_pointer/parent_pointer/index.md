# nlohmann::json_pointer::parent_pointer

```
json_pointer parent_pointer() const;
```

Returns the parent of this JSON pointer.

## Return value

Parent of this JSON pointer; in case this JSON pointer is the root, the root itself is returned.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Linear in the length of the JSON pointer.

## Examples

Example

The example shows the result of `parent_pointer` for different JSON Pointers.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // different JSON Pointers
    json::json_pointer ptr1("");
    json::json_pointer ptr2("/foo");
    json::json_pointer ptr3("/foo/0");

    // call parent_pointer()
    std::cout << std::boolalpha
              << "parent of \"" << ptr1 << "\" is \"" << ptr1.parent_pointer() << "\"\n"
              << "parent of \"" << ptr2 << "\" is \"" << ptr2.parent_pointer() << "\"\n"
              << "parent of \"" << ptr3 << "\" is \"" << ptr3.parent_pointer() << "\"" << std::endl;
}
```

Output:

```
parent of "" is ""
parent of "/foo" is ""
parent of "/foo/0" is "/foo"
```

## See also

- [pop_back](https://json.nlohmann.me/api/json_pointer/pop_back/index.md) remove the last reference token
- [back](https://json.nlohmann.me/api/json_pointer/back/index.md) return the last reference token

## Version history

Added in version 3.6.0.
