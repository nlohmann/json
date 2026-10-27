# <small>nlohmann::basic_json::</small>value_t

```cpp
enum class value_t : std::uint8_t {
    null,
    object,
    array,
    string,
    boolean,
    number_integer,
    number_unsigned,
    number_float,
    binary,
    discarded
};
```

This enumeration collects the different JSON types. It is internally used to distinguish the stored values, and the
functions [`is_null`](is_null.md), [`is_object`](is_object.md), [`is_array`](is_array.md), [`is_string`](is_string.md),
[`is_boolean`](is_boolean.md), [`is_number`](is_number.md) (with [`is_number_integer`](is_number_integer.md),
[`is_number_unsigned`](is_number_unsigned.md), and [`is_number_float`](is_number_float.md)),
[`is_discarded`](is_discarded.md), [`is_binary`](is_binary.md), [`is_primitive`](is_primitive.md), and
[`is_structured`](is_structured.md) rely on it.

## Notes

!!! note "Ordering"

    The order of types is as follows:

    1. `null`
    2. `boolean`
    3. `number_integer`, `number_unsigned`, `number_float`
    4. `object`
    5. `array`
    6. `string`
    7. `binary`

    `discarded` is unordered.

    ```mermaid
    flowchart LR
        A[null] --> B[boolean]
        B --> C["number_integer / number_unsigned / number_float"]
        C --> D[object]
        D --> E[array]
        E --> F[string]
        F --> G[binary]
    ```

    <p class="nj-caption" markdown>Arrows point from a type to the next greater type in the ordering used by
    `operator<`.</p>

!!! note "Types of numbers"

    There are three enumerators for numbers (`number_integer`, `number_unsigned`, and `number_float`) to distinguish
    between different types of numbers:

      - [`number_unsigned_t`](number_unsigned_t.md) for unsigned integers
      - [`number_integer_t`](number_integer_t.md) for signed integers
      - [`number_float_t`](number_float_t.md) for floating-point numbers or to approximate integers which do not fit
        into the limits of their respective type

!!! warning "Comparison operators"

    `operator<` and `operator<=>` (since C++20) are overloaded and compare according to the ordering described above.
    Until C++20 all other relational and equality operators yield results according to the integer value of each
    enumerator. Since C++20 some compilers consider the _rewritten candidates_ generated from `operator<=>` during
    overload resolution, while others do not. For predictable and portable behavior use:

      - `operator<` or `operator<=>` when wanting to compare according to the order described above
      - `operator==` or `operator!=` when wanting to compare according to each enumerators integer value

## Examples

??? example

    The following code how `type()` queries the `value_t` for all JSON types.
    
    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
    int main()
    {
        // create JSON values
        json j_null;
        json j_boolean = true;
        json j_number_integer = -17;
        json j_number_unsigned = 42u;
        json j_number_float = 23.42;
        json j_object = {{"one", 1}, {"two", 2}};
        json j_array = {1, 2, 4, 8, 16};
        json j_string = "Hello, world";
    
        // call type()
        std::cout << std::boolalpha;
        std::cout << (j_null.type() == json::value_t::null) << '\n';
        std::cout << (j_boolean.type() == json::value_t::boolean) << '\n';
        std::cout << (j_number_integer.type() == json::value_t::number_integer) << '\n';
        std::cout << (j_number_unsigned.type() == json::value_t::number_unsigned) << '\n';
        std::cout << (j_number_float.type() == json::value_t::number_float) << '\n';
        std::cout << (j_object.type() == json::value_t::object) << '\n';
        std::cout << (j_array.type() == json::value_t::array) << '\n';
        std::cout << (j_string.type() == json::value_t::string) << '\n';
    }
    
    ```
    
    Output:
    
    ```json
    true
    true
    true
    true
    true
    true
    true
    true
    
    ```

## See also

- [`type`](type.md) - return the type of the JSON value
- [`type_name`](type_name.md) - return the type as string
- [`operator value_t`](operator_value_t.md) - return the type of the JSON value
- [`is_primitive`](is_primitive.md) - return whether the type is primitive
- [`is_structured`](is_structured.md) - return whether the type is structured
- [Types](../../features/types/index.md) - the JSON value types and how they are stored

## Version history

- Added in version 1.0.0.
- Added unsigned integer type in version 2.0.0.
- Added binary type in version 3.8.0.
