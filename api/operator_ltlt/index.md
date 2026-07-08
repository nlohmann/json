# nlohmann::operator\<<(basic_json), nlohmann::operator\<<(json_pointer)

```
std::ostream& operator<<(std::ostream& o, const basic_json& j);      // (1)

std::ostream& operator<<(std::ostream& o, const json_pointer& ptr);  // (2)
```

1. Serialize the given JSON value `j` to the output stream `o`. The JSON value will be serialized using the [`dump`](https://json.nlohmann.me/api/basic_json/dump/index.md) member function.
   - The indentation of the output can be controlled with the member variable `width` of the output stream `o`. For instance, using the manipulator `std::setw(4)` on `o` sets the indentation level to `4` and the serialization result is the same as calling `dump(4)`.
   - The indentation character can be controlled with the member variable `fill` of the output stream `o`. For instance, the manipulator `std::setfill('\\t')` sets indentation to use a tab character rather than the default space character.
1. Write a string representation of the given JSON pointer `ptr` to the output stream `o`. The string representation is obtained using the [`to_string`](https://json.nlohmann.me/api/json_pointer/to_string/index.md) member function.

## Parameters

`o` (in, out) : stream to write to

`j` (in) : JSON value to serialize

`ptr` (in) : JSON pointer to write

## Return value

the stream `o`

## Exceptions

1. Throws [`type_error.316`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error316) if a string stored inside the JSON value is not UTF-8 encoded. Note that unlike the [`dump`](https://json.nlohmann.me/api/basic_json/dump/index.md) member functions, no `error_handler` can be set.
1. None.

## Complexity

Linear.

## Notes

Deprecation

Function `std::ostream& operator<<(std::ostream& o, const basic_json& j)` replaces function `std::ostream& operator>>(const basic_json& j, std::ostream& o)` which has been deprecated in version 3.0.0. It will be removed in version 4.0.0. Please replace calls like `j >> o;` with `o << j;`.

## Examples

Example: (1) serialize JSON value to stream

The example below shows the serialization with different parameters to `width` to adjust the indentation level.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON values
    json j_object = {{"one", 1}, {"two", 2}};
    json j_array = {1, 2, 4, 8, 16};

    // serialize without indentation
    std::cout << j_object << "\n\n";
    std::cout << j_array << "\n\n";

    // serialize with indentation
    std::cout << std::setw(4) << j_object << "\n\n";
    std::cout << std::setw(2) << j_array << "\n\n";
    std::cout << std::setw(1) << std::setfill('\t') << j_object << "\n\n";
}
```

Output:

```
{"one":1,"two":2}

[1,2,4,8,16]

{
    "one": 1,
    "two": 2
}

[
  1,
  2,
  4,
  8,
  16
]

{
    "one": 1,
    "two": 2
}
```

Example: (2) write JSON pointer to stream

The example below shows how to write a JSON pointer to a stream.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON pointer
    json::json_pointer ptr("/foo/bar/baz");

    // write string representation to stream
    std::cout << ptr << std::endl;
}
```

Output:

```
/foo/bar/baz
```

## See also

- [dump](https://json.nlohmann.me/api/basic_json/dump/index.md) - serialize to a JSON-formatted string
- [Serialization](https://json.nlohmann.me/features/serialization/index.md) - the serialization article

## Version history

1. Added in version 1.0.0. Added support for indentation character and deprecated `std::ostream& operator>>(const basic_json& j, std::ostream& o)` in version 3.0.0.
1. Added in version 3.11.0.
