# nlohmann::basic_json::boolean_t

```
using boolean_t = BooleanType;
```

The type used to store JSON booleans.

[RFC 8259](https://tools.ietf.org/html/rfc8259) implicitly describes a boolean as a type which differentiates the two literals `true` and `false`.

To store boolean values in C++, a type is defined by the template parameter `BooleanType` which chooses the type to use.

## Notes

#### Default type

With the default values for `BooleanType` (`bool`), the default value for `boolean_t` is `bool`.

#### Storage

Boolean values are stored directly inside a `basic_json` type.

## Examples

Example

The following code shows that `boolean_t` is by default, a typedef to `bool`.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    std::cout << std::boolalpha << std::is_same<bool, json::boolean_t>::value << std::endl;
}
```

Output:

```
true
```

## Version history

- Added in version 1.0.0.
