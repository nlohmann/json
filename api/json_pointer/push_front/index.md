# nlohmann::json_pointer::push_front

```
void push_front(const string_t& token);

void push_front(string_t&& token);
```

Append an unescaped token at the start of the reference pointer.

## Parameters

`token` (in) : token to add

## Complexity

Linear in the number of reference tokens in the `json_pointer`.

## Examples

Example

The example shows the result of `push_front` for different JSON Pointers.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create empty JSON Pointer
    json::json_pointer ptr;
    std::cout << "\"" << ptr << "\"\n";

    // call push_front()
    ptr.push_front("foo");
    std::cout << "\"" << ptr << "\"\n";

    ptr.push_front("0");
    std::cout << "\"" << ptr << "\"\n";

    ptr.push_front("bar");
    std::cout << "\"" << ptr << "\"\n";
}
```

Output:

```
""
"/foo"
"/0/foo"
"/bar/0/foo"
```

## Version history

- Added in version 3.13.0.
