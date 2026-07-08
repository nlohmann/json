# to_string(basic_json)

```
template <typename BasicJsonType>
std::string to_string(const BasicJsonType& j);
```

This function implements a user-defined to_string for JSON objects.

## Template parameters

`BasicJsonType` : a specialization of [`basic_json`](https://json.nlohmann.me/api/basic_json/index.md)

## Return value

string containing the serialization of the JSON value

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes to any JSON value.

## Exceptions

Throws [`type_error.316`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error316) if a string stored inside the JSON value is not UTF-8 encoded

## Complexity

Linear.

## Possible implementation

```
template <typename BasicJsonType>
std::string to_string(const BasicJsonType& j)
{
    return j.dump();
}
```

## Examples

Example

The following code shows how the library's `to_string()` function integrates with others, allowing argument-dependent lookup.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using std::to_string;

int main()
{
    // create values
    json j = {{"one", 1}, {"two", 2}};
    int i = 42;

    // use ADL to select best to_string function
    auto j_str = to_string(j);  // calling nlohmann::to_string
    auto i_str = to_string(i);  // calling std::to_string

    // serialize without indentation
    std::cout << j_str << "\n\n"
              << i_str << std::endl;
}
```

Output:

```
{"one":1,"two":2}

42
```

## See also

- [dump](https://json.nlohmann.me/api/basic_json/dump/index.md)
- [Serialization](https://json.nlohmann.me/features/serialization/index.md) - the serialization article

## Version history

Added in version 3.7.0.
