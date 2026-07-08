# nlohmann::json_pointer::string_t

```
using string_t = RefStringType;
```

The string type used for the reference tokens making up the JSON pointer.

See [`basic_json::string_t`](https://json.nlohmann.me/api/basic_json/string_t/index.md) for more information.

## Examples

Example

The example shows the type `string_t` and its relation to `basic_json::string_t`.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    json::json_pointer::string_t s = "This is a string.";

    std::cout << s << std::endl;

    std::cout << std::boolalpha << std::is_same<json::json_pointer::string_t, json::string_t>::value << std::endl;
}
```

Output:

```
This is a string.
true
```

## Version history

- Added in version 3.11.0.
