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
    Enforced by static assertion.

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

!!! warning

    Writing data to the referee of the result yields an undefined state.

## Examples

??? example

    The example shows several calls to `get_ref()`.
    
    ```cpp
    --8<-- "examples/get_ref.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/get_ref.output"
    ```

## Version history

- Added in version 1.1.0.
- Extended to binary types in version 3.8.0.
