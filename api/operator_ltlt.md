# <small>nlohmann::</small>operator<<(basic_json), <small>nlohmann::</small>operator<<(json_pointer)

```cpp
std::ostream& operator<<(std::ostream& o, const basic_json& j);      // (1)

std::ostream& operator<<(std::ostream& o, const json_pointer& ptr);  // (2)
```

1. Serialize the given JSON value `j` to the output stream `o`. The JSON value will be serialized using the
   [`dump`](basic_json/dump.md) member function.
    - The indentation of the output can be controlled with the member variable `width` of the output stream `o`. For
      instance, using the manipulator `std::setw(4)` on `o` sets the indentation level to `4` and the serialization
      result is the same as calling `dump(4)`.
    - The indentation character can be controlled with the member variable `fill` of the output stream `o`.
      For instance, the manipulator `std::setfill('\\t')` sets indentation to use a tab character rather than the
      default space character.
2. Write a string representation of the given JSON pointer `ptr` to the output stream `o`. The string representation is
   obtained using the [`to_string`](json_pointer/to_string.md) member function.

## Parameters

`o` (in, out)
:   stream to write to

`j` (in)
:   JSON value to serialize

`ptr` (in)
:   JSON pointer to write

## Return value

the stream `o`

## Exceptions

1. Throws [`type_error.316`](../home/exceptions.md#jsonexceptiontype_error316) if a string stored inside the JSON
   value is not UTF-8 encoded. Note that unlike the [`dump`](basic_json/dump.md) member functions, no `error_handler`
   can be set.
2. Throws no library exceptions. As the string representation is built with [`to_string`](json_pointer/to_string.md),
   `#!cpp std::bad_alloc` is possible.

## Complexity

Linear.

## Notes

!!! warning "Deprecation"

    Function  `#!cpp std::ostream& operator<<(std::ostream& o, const basic_json& j)` replaces function
    `#!cpp std::ostream& operator>>(const basic_json& j, std::ostream& o)` which has been deprecated in version 3.0.0.
    It will be removed in version 4.0.0. Please replace calls like `#!cpp j >> o;` with `#!cpp o << j;`.

    See the [migration guide](../integration/migration_guide.md#miscellaneous-functions) for how to update existing code.

## Examples

??? example "Example: (1) serialize JSON value to stream"

    The example below shows the serialization with different parameters to `width` to adjust the indentation level.
    
    ```cpp
    #include <iostream>
    #include <iomanip>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
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
    
    ```json
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

??? example "Example: (2) write JSON pointer to stream"

    The example below shows how to write a JSON pointer to a stream.
    
    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
    int main()
    {
        // create JSON pointer
        json::json_pointer ptr("/foo/bar/baz");
    
        // write string representation to stream
        std::cout << ptr << '\n';
    }
    
    ```
    
    Output:
    
    ```json
    /foo/bar/baz
    
    ```

## See also

- [dump](basic_json/dump.md) - serialize to a JSON-formatted string
- [`basic_json_view::operator<<`](basic_json_view/operator_ltlt.md) - the corresponding operator for
  `basic_json_view`
- [Serialization](../features/serialization.md) - the serialization article

## Version history

1. Added in version 1.0.0. Added support for indentation character and deprecated
   `#!cpp std::ostream& operator>>(const basic_json& j, std::ostream& o)` in version 3.0.0.
2. Added in version 3.11.0.
