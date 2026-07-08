# nlohmann::json_pointer::operator/=

```
// (1)
json_pointer& operator/=(const json_pointer& ptr);

// (2)
json_pointer& operator/=(string_t token);

// (3)
json_pointer& operator/=(std::size_t array_idx)
```

1. append another JSON pointer at the end of this JSON pointer
1. append an unescaped reference token at the end of this JSON pointer
1. append an array index at the end of this JSON pointer

## Parameters

`ptr` (in) : JSON pointer to append

`token` (in) : reference token to append

`array_idx` (in) : array index to append

## Return value

1. JSON pointer with `ptr` appended
1. JSON pointer with `token` appended without escaping `token`
1. JSON pointer with `array_idx` appended

## Complexity

1. Linear in the length of `ptr`.
1. Amortized constant.
1. Amortized constant.

## Examples

Example

The example shows the usage of `operator/=`.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON pointer
    json::json_pointer ptr("/foo");
    std::cout << "\"" << ptr << "\"\n";

    // append a JSON Pointer
    ptr /= json::json_pointer("/bar/baz");
    std::cout << "\"" << ptr << "\"\n";

    // append a string
    ptr /= "fob";
    std::cout << "\"" << ptr << "\"\n";

    // append an array index
    ptr /= 42;
    std::cout << "\"" << ptr << "\"" << std::endl;
}
```

Output:

```
"/foo"
"/foo/bar/baz"
"/foo/bar/baz/fob"
"/foo/bar/baz/fob/42"
```

## Version history

1. Added in version 3.6.0.
1. Added in version 3.6.0. Changed type of `token` to `string_t` in version 3.11.0.
1. Added in version 3.6.0.
