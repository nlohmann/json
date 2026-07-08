# nlohmann::json_pointer::push_back

```
void push_back(const string_t& token);

void push_back(string_t&& token);
```

Append an unescaped token at the end of the reference pointer.

## Parameters

`token` (in) : token to add

## Complexity

Amortized constant.

## Examples

Example

The example shows the result of `push_back` for different JSON Pointers.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create empty JSON Pointer
    json::json_pointer ptr;
    std::cout << "\"" << ptr << "\"\n";

    // call push_back()
    ptr.push_back("foo");
    std::cout << "\"" << ptr << "\"\n";

    ptr.push_back("0");
    std::cout << "\"" << ptr << "\"\n";

    ptr.push_back("bar");
    std::cout << "\"" << ptr << "\"\n";
}
```

Output:

```
""
"/foo"
"/foo/0"
"/foo/0/bar"
```

## Version history

- Added in version 3.6.0.
- Changed type of `token` to `string_t` in version 3.11.0.
