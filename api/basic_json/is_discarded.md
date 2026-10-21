# <small>nlohmann::basic_json::</small>is_discarded

```cpp
constexpr bool is_discarded() const noexcept;
```

This function returns `#!cpp true` for a JSON value if either:

- the value was discarded during parsing with a callback function (see [`parser_callback_t`](parser_callback_t.md)), or
- the value is the result of parsing invalid JSON with parameter `allow_exceptions` set to `#!cpp false`; see
  [`parse`](parse.md) for more information.

## Return value

`#!cpp true` if type is discarded, `#!cpp false` otherwise.

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Notes

!!! note "Comparisons"

    Discarded values are never compared equal with [`operator==`](operator_eq.md). That is, checking whether a JSON
    value `j` is discarded will only work via:
    
    ```cpp
    j.is_discarded()
    ```
    
    because
    
    ```cpp
    j == json::value_t::discarded
    ```
    
    will always be `#!cpp false`.

!!! note "Removal during parsing with callback functions"

    When a value is discarded by a callback function (see [`parser_callback_t`](parser_callback_t.md)) during parsing,
    then it is removed when it is part of a structured value. For instance, if the second value of an array is discarded,
    instead of `#!json [null, discarded, false]`, the array `#!json [null, false]` is returned. If the top-level value
    itself is discarded by the callback, the `parse` call returns a `#!json null` value.

After a successful parse, this function always returns `#!cpp false`: discarded values can only occur during parsing and
are either removed when inside a structured value or replaced by `#!json null` at the top level. The exception is parsing
with `allow_exceptions` set to `#!cpp false`: a parse error then yields a discarded value for which this function returns
`#!cpp true` (see [`parse`](parse.md)).

## Examples

??? example "Example: `is_discarded()` for ordinary JSON values"

    The following code exemplifies `is_discarded()` for all JSON types.
    
    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using json = nlohmann::json;
    
    int main()
    {
        // create JSON values
        json j_null;
        json j_boolean = true;
        json j_number_integer = 17;
        json j_number_unsigned_integer = 12345678987654321u;
        json j_number_float = 23.42;
        json j_object = {{"one", 1}, {"two", 2}};
        json j_array = {1, 2, 4, 8, 16};
        json j_string = "Hello, world";
        json j_binary = json::binary({1, 2, 3});
    
        // call is_discarded()
        std::cout << std::boolalpha;
        std::cout << j_null.is_discarded() << '\n';
        std::cout << j_boolean.is_discarded() << '\n';
        std::cout << j_number_integer.is_discarded() << '\n';
        std::cout << j_number_unsigned_integer.is_discarded() << '\n';
        std::cout << j_number_float.is_discarded() << '\n';
        std::cout << j_object.is_discarded() << '\n';
        std::cout << j_array.is_discarded() << '\n';
        std::cout << j_string.is_discarded() << '\n';
        std::cout << j_binary.is_discarded() << '\n';
    }
    
    ```
    
    Output:
    
    ```json
    false
    false
    false
    false
    false
    false
    false
    false
    false
    
    ```

??? example "Example: discarded values from parsing"

    The following code shows the two situations in which a discarded value can be observed: parsing invalid JSON with
    `allow_exceptions` set to `#!cpp false`, and a parser callback that discards the top-level value (which is replaced
    by `#!json null` and therefore does *not* remain discarded).

    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using json = nlohmann::json;
    
    int main()
    {
        // parsing invalid JSON without exceptions yields a discarded value
        json j_invalid = json::parse("[1,2,3", nullptr, false);
    
        // a callback that discards the top-level value does not leave it
        // "discarded" -- it is replaced by null instead
        json j_discarded_by_callback = json::parse("[1,2,3]", [](int /*depth*/, json::parse_event_t event, json& /*parsed*/)
        {
            return event != json::parse_event_t::array_start;
        });
    
        std::cout << std::boolalpha;
        std::cout << "j_invalid.is_discarded()               = " << j_invalid.is_discarded() << '\n';
        std::cout << "j_discarded_by_callback                = " << j_discarded_by_callback << '\n';
        std::cout << "j_discarded_by_callback.is_discarded() = " << j_discarded_by_callback.is_discarded() << '\n';
    }
    
    ```

    Output:

    ```json
    j_invalid.is_discarded()               = true
    j_discarded_by_callback                = null
    j_discarded_by_callback.is_discarded() = false
    
    ```

## See also

- [basic_json_view::is_discarded](../basic_json_view/is_discarded.md) - the corresponding check on a zero-copy view,
  which is `#!cpp true` if the view refers to no value

## Version history

- Added in version 1.0.0.
