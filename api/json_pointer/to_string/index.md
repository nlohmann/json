# nlohmann::json_pointer::to_string

```
string_t to_string() const;
```

Return a string representation of the JSON pointer.

## Return value

A string representation of the JSON pointer

## Notes

For each JSON pointer `ptr`, it holds:

```
ptr == json_pointer(ptr.to_string());
```

## Examples

Example

The example shows the result of `to_string`.

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
    json::json_pointer ptr4("/");
    json::json_pointer ptr5("/a~1b");
    json::json_pointer ptr6("/c%d");
    json::json_pointer ptr7("/e^f");
    json::json_pointer ptr8("/g|h");
    json::json_pointer ptr9("/i\\j");
    json::json_pointer ptr10("/k\"l");
    json::json_pointer ptr11("/ ");
    json::json_pointer ptr12("/m~0n");

    std::cout << "\"" << ptr1.to_string() << "\"\n"
              << "\"" << ptr2.to_string() << "\"\n"
              << "\"" << ptr3.to_string() << "\"\n"
              << "\"" << ptr4.to_string() << "\"\n"
              << "\"" << ptr5.to_string() << "\"\n"
              << "\"" << ptr6.to_string() << "\"\n"
              << "\"" << ptr7.to_string() << "\"\n"
              << "\"" << ptr8.to_string() << "\"\n"
              << "\"" << ptr9.to_string() << "\"\n"
              << "\"" << ptr10.to_string() << "\"\n"
              << "\"" << ptr11.to_string() << "\"\n"
              << "\"" << ptr12.to_string() << "\"" << std::endl;
}
```

Output:

```
""
"/foo"
"/foo/0"
"/"
"/a~1b"
"/c%d"
"/e^f"
"/g|h"
"/i\j"
"/k"l"
"/ "
"/m~0n"
```

## Version history

- Since version 2.0.0.
- Changed return type to `string_t` in version 3.11.0.
