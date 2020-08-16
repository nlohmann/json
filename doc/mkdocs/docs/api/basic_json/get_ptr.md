# basic_json::get_ptr

```cpp
template<typename PointerType>
PointerType get_ptr();

template<typename PointerType>
constexpr const PointerType get_ptr() const noexcept;
```

Implicit pointer access to the internally stored JSON value. No copies are made.

## Template arguments

`PointerType`
:   pointer type; must be a pointer to [`array_t`](array_t.md), [`object_t`](object_t.md), [`string_t`](string_t.md),
    [`boolean_t`](boolean_t.md), [`number_integer_t`](number_integer_t.md), or
    [`number_unsigned_t`](number_unsigned_t.md), [`number_float_t`](number_float_t.md), or [`binary_t`](binary_t.md).
    Other types will not compile.

## Return value

pointer to the internally stored JSON value if the requested pointer type fits to the JSON value; `#!cpp nullptr`
otherwise

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Complexity

Constant.

## Notes

!!! warning

    Writing data to the pointee of the result yields an undefined state.

## Example

??? example

    The example below shows how pointers to internal values of a JSON value can be requested. Note that no type
    conversions are made and a `#!cpp nullptr` is returned if the value and the requested pointer type does not match.
    
    ```cpp
    --8<-- "examples/get_ptr.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/get_ptr.output"
    ```

## Version history

- Added in version 1.0.0.
- Extended to binary types in version 3.8.0.
