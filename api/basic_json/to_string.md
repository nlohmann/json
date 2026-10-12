# to_string(basic_json)

```cpp
template <typename BasicJsonType>
std::string to_string(const BasicJsonType& j);
```

This function implements a user-defined to_string for JSON objects.

## Template parameters

`BasicJsonType`
:   a specialization of [`basic_json`](index.md) whose [`string_t`](string_t.md) is convertible to `#!cpp std::string`;
    for other string types, use [`dump`](dump.md), which returns a `string_t`

## Return value

string containing the serialization of the JSON value

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes to any JSON value.

## Exceptions

Throws [`type_error.316`](../../home/exceptions.md#jsonexceptiontype_error316) if a string stored inside the JSON value
is not UTF-8 encoded

## Complexity

Linear.

## Possible implementation

```cpp
template <typename BasicJsonType>
std::string to_string(const BasicJsonType& j)
{
    return j.dump();
}
```

## Examples

??? example

    The following code shows how the library's `to_string()` function integrates with others, allowing
    argument-dependent lookup.
     
    ```cpp
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
    
    ```json
    {"one":1,"two":2}
    
    42
    
    ```

## See also

- [dump](dump.md)
- [Serialization](../../features/serialization.md) - the serialization article

## Version history

Added in version 3.7.0.
