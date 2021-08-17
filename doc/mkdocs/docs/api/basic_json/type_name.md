# basic_json::type_name

```cpp
const char* type_name() const noexcept;
```

Returns the type name as string to be used in error messages -- usually to indicate that a function was called on a
wrong JSON type.
    
## Return value

a string representation of a the type ([`value_t`](value_t.md)):

Value type                                         | return value
-------------------------------------------------- | -------------------------
`#!json null`                                      | `"null"`
boolean                                            | `"boolean"`
string                                             | `"string"`
number (integer, unsigned integer, floating-point) | `"number"`
object                                             | `"object`
array                                              | `"array`
binary                                             | `"binary`
discarded                                          | `"discarded`

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Example

??? example

    The following code exemplifies `type_name()` for all JSON types.
    
    ```cpp
    --8<-- "examples/type_name.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/type_name.output"
    ```

## Version history

- Added in version 1.0.0.
- Part of the public API version since 2.1.0.
- Changed return value to `const char*` and added `noexcept` in version 3.0.0.
- Added support for binary type in version 3.8.0.
