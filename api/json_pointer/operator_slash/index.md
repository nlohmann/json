# nlohmann::json_pointer::operator/

```
// (1)
json_pointer operator/(const json_pointer& lhs, const json_pointer& rhs);

// (2)
json_pointer operator/(const json_pointer& lhs, string_t token);

// (3)
json_pointer operator/(const json_pointer& lhs, std::size_t array_idx);
```

1. create a new JSON pointer by appending the right JSON pointer at the end of the left JSON pointer
1. create a new JSON pointer by appending the unescaped token at the end of the JSON pointer
1. create a new JSON pointer by appending the array-index-token at the end of the JSON pointer

## Parameters

`lhs` (in) : JSON pointer

`rhs` (in) : JSON pointer to append

`token` (in) : reference token to append

`array_idx` (in) : array index to append

## Return value

1. a new JSON pointer with `rhs` appended to `lhs`
1. a new JSON pointer with unescaped `token` appended to `lhs`
1. a new JSON pointer with `array_idx` appended to `lhs`

## Complexity

1. Linear in the length of `lhs` and `rhs`.
1. Linear in the length of `lhs`.
1. Linear in the length of `lhs`.

## Examples

Example

The example shows the usage of `operator/`.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON pointer
    json::json_pointer ptr("/foo");

    // append a JSON Pointer
    std::cout << "\"" << ptr / json::json_pointer("/bar/baz") << "\"\n";

    // append a string
    std::cout << "\"" << ptr / "fob" << "\"\n";

    // append an array index
    std::cout << "\"" << ptr / 42 << "\"" << std::endl;
}
```

Output:

```
"/foo/bar/baz"
"/foo/fob"
"/foo/42"
```

## Version history

1. Added in version 3.6.0.
1. Added in version 3.6.0. Changed type of `token` to `string_t` in version 3.11.0.
1. Added in version 3.6.0.
