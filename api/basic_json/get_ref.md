# <small>nlohmann::basic_json::</small>get_ref

```cpp
template<typename ReferenceType>
ReferenceType get_ref();

template<typename ReferenceType>
const ReferenceType get_ref() const;
```

Implicit reference access to the internally stored JSON value. No copies are made.

## Template parameters

`ReferenceType`
:   reference type; must be a reference to [`array_t`](array_t.md), [`object_t`](object_t.md),
    [`string_t`](string_t.md), [`boolean_t`](boolean_t.md), [`number_integer_t`](number_integer_t.md), or
    [`number_unsigned_t`](number_unsigned_t.md), [`number_float_t`](number_float_t.md), or [`binary_t`](binary_t.md).
    Enforced by a static assertion.

## Return value

reference to the internally stored JSON value if the requested reference type fits to the JSON value; throws
[`type_error.303`](../../home/exceptions.md#jsonexceptiontype_error303) otherwise

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Exceptions

Throws [`type_error.303`](../../home/exceptions.md#jsonexceptiontype_error303) if the requested reference type does not
match the stored JSON value type; example: `"incompatible ReferenceType for get_ref, actual type is binary"`.

## Complexity

Constant.

## Notes

!!! danger "Undefined behavior"

    The reference becomes invalid if the underlying JSON object changes.

## Examples

??? example

    The example shows several calls to `get_ref()`.
    
    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
    int main()
    {
        // create a JSON number
        json value = 17;
    
        // explicitly getting references
        auto r1 = value.get_ref<const json::number_integer_t&>();
        auto r2 = value.get_ref<json::number_integer_t&>();
    
        // print the values
        std::cout << r1 << ' ' << r2 << '\n';
    
        // incompatible type throws exception
        try
        {
            auto r3 = value.get_ref<json::number_float_t&>();
        }
        catch (const json::type_error& ex)
        {
            std::cout << ex.what() << '\n';
        }
    }
    
    ```
    
    Output:
    
    ```json
    17 17
    [json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is number
    
    ```

## See also

- [`get_ptr()`](get_ptr.md) - get a pointer value
- [`basic_json_view::get_string`](../basic_json_view/get_string.md) - the closest counterpart on a zero-copy view: a
  string without a copy, but as a view rather than a reference to a value that must already exist
- [Converting values](../../features/conversions.md) - getting values out, with or without copying

## Version history

- Added in version 1.1.0.
- Extended to binary types in version 3.8.0.
