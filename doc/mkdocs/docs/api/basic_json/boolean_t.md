# <small>nlohmann::basic_json::</small>boolean_t

```cpp
using boolean_t = BooleanType;
```

The type used to store JSON booleans.

[RFC 8259](https://tools.ietf.org/html/rfc8259) implicitly describes a boolean as a type which differentiates the two literals
`#!json true` and `#!json false`.

To store objects in C++, a type is defined by the template parameter  `BooleanType` which chooses the type to use.

## Notes

#### Default type

With the default values for `BooleanType` (`#!cpp bool`), the default value for `boolean_t` is `#!cpp bool`.

#### Storage

Boolean values are stored directly inside a `basic_json` type.

## Examples

??? example

    The following code shows that `boolean_t` is by default, a typedef to `#!cpp bool`.
     
    ```cpp
    --8<-- "examples/boolean_t.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/boolean_t.output"
    ```

## Version history

- Added in version 1.0.0.
