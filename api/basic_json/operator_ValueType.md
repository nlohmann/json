# <small>nlohmann::basic_json::</small>operator ValueType

```cpp
template<typename ValueType>
JSON_EXPLICIT operator ValueType() const;
```

Implicit type conversion between the JSON value and a compatible value. The call is realized by calling
[`get()`](get.md). See [Notes](#notes) for the meaning of `JSON_EXPLICIT`.

## Template parameters

`ValueType`
:   the value type to return

## Return value

copy of the JSON value, converted to `ValueType`

## Exception safety

Depends on what `json_serializer<ValueType>` `from_json()` method throws; the JSON value itself is never modified,
since `#!cpp operator ValueType()` is a `#!cpp const` member function that only calls [`get()`](get.md).

## Exceptions

Depends on what `json_serializer<ValueType>` `from_json()` method throws

## Complexity

Linear in the size of the JSON value.

## Notes

!!! note "Definition of `JSON_EXPLICIT`"

    By default `JSON_EXPLICIT` is defined to the empty string, so the signature is:
    
    ```cpp
    template<typename ValueType>
    operator ValueType() const;
    ```
    
    If [`JSON_USE_IMPLICIT_CONVERSIONS`](../macros/json_use_implicit_conversions.md) is set to `0`,
    `JSON_EXPLICIT` is defined to `#!cpp explicit`:

    ```cpp
    template<typename ValueType>
    explicit operator ValueType() const;
    ```
    
    That is, implicit conversions can be switched off by defining
    [`JSON_USE_IMPLICIT_CONVERSIONS`](../macros/json_use_implicit_conversions.md) to `0`.

!!! info "Future behavior change"

    Implicit conversions will be switched off by default in the next major release of the library. That is,
    `JSON_EXPLICIT` will be set to `#!cpp explicit` by default.

    You can prepare existing code by already defining
    [`JSON_USE_IMPLICIT_CONVERSIONS`](../macros/json_use_implicit_conversions.md) to `0` and replace any implicit
    conversions with calls to [`get`](../basic_json/get.md).

    See the [migration guide](../../integration/migration_guide.md#replace-implicit-conversions) for how to update existing code.

## Examples

??? example

    The example below shows several conversions from JSON values to other types. There are a few things to note: (1)
    Floating-point numbers can be converted to integers, (2) A JSON array can be converted to a standard
    `std::vector<short>`, (3) A JSON object can be converted to C++ associative containers such as
    `std::map<std::string, json>`.
        
    ```cpp
    #include <iostream>
    #include <map>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
    int main()
    {
        // create a JSON value with different types
        json json_types =
        {
            {"boolean", true},
            {
                "number", {
                    {"integer", 42},
                    {"floating-point", 17.23}
                }
            },
            {"string", "Hello, world!"},
            {"array", {1, 2, 3, 4, 5}},
            {"null", nullptr}
        };
    
        // use implicit conversions
        bool v1 = json_types["boolean"];
        int v2 = json_types["number"]["integer"];
        short v3 = json_types["number"]["integer"];
        float v4 = json_types["number"]["floating-point"];
        int v5 = json_types["number"]["floating-point"];
        std::string v6 = json_types["string"];
        std::vector<short> v7 = json_types["array"];
        std::map<std::string, json> v8 = json_types;
    
        // print the conversion results
        std::cout << v1 << '\n';
        std::cout << v2 << ' ' << v3 << '\n';
        std::cout << v4 << ' ' << v5 << '\n';
        std::cout << v6 << '\n';
    
        for (auto i : v7)
        {
            std::cout << i << ' ';
        }
        std::cout << "\n\n";
    
        for (const auto& i : v8)
        {
            std::cout << i.first << ": " << i.second << '\n';
        }
    
        // example for an exception
        try
        {
            bool v1 = json_types["string"];
        }
        catch (const json::type_error& e)
        {
            std::cout << e.what() << '\n';
        }
    }
    
    ```
    
    Output:
    
    ```json
    1
    42 42
    17.23 17
    Hello, world!
    1 2 3 4 5 
    
    array: [1,2,3,4,5]
    boolean: true
    null: null
    number: {"floating-point":17.23,"integer":42}
    string: "Hello, world!"
    [json.exception.type_error.302] type must be boolean, but is string
    
    ```

## See also

- [get](get.md) get a value (explicit conversion)
- [Converting values](../../features/conversions.md) - the type conversions article

## Version history

- Added in version 1.0.0.
- Macros `JSON_EXPLICIT`/[`JSON_USE_IMPLICIT_CONVERSIONS`](../macros/json_use_implicit_conversions.md) added
  in version 3.9.0.
