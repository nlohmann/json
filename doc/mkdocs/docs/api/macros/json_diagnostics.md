# JSON_DIAGNOSTICS

```cpp
#define JSON_DIAGNOSTICS /* value */
```

This macro enables [extended diagnostics for exception messages](../../home/exceptions.md#extended-diagnostic-messages).
Possible values are `1` to enable or `0` to disable (default).

When enabled, exception messages contain a [JSON Pointer](../json_pointer/json_pointer.md) to the JSON value that
triggered the exception. Note that enabling this macro increases the size of every JSON value by one pointer and adds
some  runtime overhead.

The diagnostics messages can also be controlled with the CMake option `JSON_Diagnostics` (`OFF` by default) which sets
`JSON_DIAGNOSTICS` accordingly.

## Default definition

The default value is `0` (extended diagnostics are switched off).

```cpp
#define JSON_DIAGNOSTICS 0
```

When the macro is not defined, the library will define it to its default value.

## Notes

!!! danger "ABI incompatibility"

    As this macro changes the definition of the `basic_json` object, it MUST be defined in the same way globally, even
    across different compilation units: `basic_json` objects with differently defined `JSON_DIAGNOSTICS` macros are
    not compatible!

## Examples

??? example "Example 1: default behavior"

    ```cpp
    --8<-- "examples/diagnostics_standard.cpp"
    ```
    
    Output:

    ```
    --8<-- "examples/diagnostics_standard.output"
    ```

    This exception can be hard to debug if storing the value `#!c "12"` and accessing it is further apart.

??? example "Example 2: extended diagnostic messages"

    ```cpp
    --8<-- "examples/diagnostics_extended.cpp"
    ```
    
    Output:

    ```
    --8<-- "examples/diagnostics_extended.output"
    ```

    Now the exception message contains a JSON Pointer `/address/housenumber` that indicates which value has the wrong type.

## Version history

- Added in version 3.10.0.
