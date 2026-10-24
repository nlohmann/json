# <small>nlohmann::basic_json::</small>get_to

```cpp
template<typename ValueType>
ValueType& get_to(ValueType& v) const noexcept(
    noexcept(JSONSerializer<ValueType>::from_json(
        std::declval<const basic_json_t&>(), v)));
```

Explicit type conversion between the JSON value and a compatible value. The value is filled into the input parameter by
calling the [`json_serializer<ValueType>`](json_serializer.md) `from_json()` method.

The function is equivalent to executing
```cpp
ValueType v;
JSONSerializer<ValueType>::from_json(*this, v);
```

This overload is chosen if:

- `ValueType` is not `basic_json`,
- `json_serializer<ValueType>` has a `from_json()` method of the form `void from_json(const basic_json&, ValueType&)`

`v` must not be `const`. Passing a `const` object is a compile-time error. For types such as arithmetic types, enums,
and C arrays, the error is a `static_assert` that names the problem. For other types, the overload is not viable, and
the compiler reports that no matching `get_to` was found.

## Template parameters

`ValueType`
:   the value type to return

## Return value

the input parameter, allowing chaining calls

## Exception safety

Depends on what `json_serializer<ValueType>` `from_json()` method throws; the JSON value itself is never modified,
since `get_to()` is a `#!cpp const` member function.

## Exceptions

Depends on what `json_serializer<ValueType>` `from_json()` method throws

## Complexity

Depends on the `json_serializer<ValueType>::from_json()` implementation.

## Examples

??? example

    The example below shows several conversions from JSON values to other types. There a few things to note: (1)
    Floating-point numbers can be converted to integers, (2) A JSON array can be converted to a standard
    `#!cpp std::vector<short>`, (3) A JSON object can be converted to C++ associative containers such as
    `#!cpp std::map<std::string, json>`.
        
    ```cpp
    #include <iostream>
    #include <map>
    #include <nlohmann/json.hpp>
    
    using json = nlohmann::json;
    
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
    
        bool v1;
        int v2;
        short v3;
        float v4;
        int v5;
        std::string v6;
        std::vector<short> v7;
        std::map<std::string, json> v8;
    
        // use explicit conversions
        json_types["boolean"].get_to(v1);
        json_types["number"]["integer"].get_to(v2);
        json_types["number"]["integer"].get_to(v3);
        json_types["number"]["floating-point"].get_to(v4);
        json_types["number"]["floating-point"].get_to(v5);
        json_types["string"].get_to(v6);
        json_types["array"].get_to(v7);
        json_types.get_to(v8);
    
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
    
        for (auto i : v8)
        {
            std::cout << i.first << ": " << i.second << '\n';
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
    
    ```

## See also

- [get](get.md) get a value (explicit conversion)
- [get_ref](get_ref.md) get a reference to the stored value
- [get_ptr](get_ptr.md) get a pointer to the stored value
- [Converting values](../../features/conversions.md) - the type conversions article
- [basic_json_view::get_to](../basic_json_view/get_to.md) - the same conversion on a zero-copy view

## Version history

- Added in version 3.3.0.
- Added a `static_assert` with a clear message for `const` arguments in version 3.13.0.
