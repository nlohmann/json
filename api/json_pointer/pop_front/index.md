# nlohmann::json_pointer::pop_front

```
void pop_front();
```

Remove the first reference token.

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Exceptions

Throws [out_of_range.405](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range405) if the JSON pointer has no parent.

## Complexity

Linear in the number of reference tokens in the `json_pointer`.

## Examples

Example

The example shows the usage of `pop_front`.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create empty JSON Pointer
    json::json_pointer ptr("/foo/bar/baz");
    std::cout << "\"" << ptr << "\"\n";

    // call pop_front()
    ptr.pop_front();
    std::cout << "\"" << ptr << "\"\n";

    ptr.pop_front();
    std::cout << "\"" << ptr << "\"\n";

    ptr.pop_front();
    std::cout << "\"" << ptr << "\"\n";
}
```

Output:

```
"/foo/bar/baz"
"/bar/baz"
"/baz"
""
```

## See also

- [front](https://json.nlohmann.me/api/json_pointer/front/index.md) return first reference token
- [push_front](https://json.nlohmann.me/api/json_pointer/push_front/index.md) append an unescaped token at the start of the pointer

## Version history

- Added in version 3.13.0 unreleased.
