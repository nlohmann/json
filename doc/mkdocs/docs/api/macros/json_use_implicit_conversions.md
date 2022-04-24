# JSON_USE_IMPLICIT_CONVERSIONS

```cpp
#define JSON_USE_IMPLICIT_CONVERSIONS /* value */
```

When defined to `0`, implicit conversions are switched off. By default, implicit conversions are switched on.

Implicit conversions can also be controlled with the CMake option `JSON_ImplicitConversions` (`ON` by default) which
sets `JSON_USE_IMPLICIT_CONVERSIONS` accordingly.

## Default definition

By default, implicit conversions are enabled.

```cpp
#define JSON_USE_IMPLICIT_CONVERSIONS 1
```

## Examples

??? example

    This is an example for an implicit conversion:

    ```cpp
    json j = "Hello, world!";
    std::string s = j;
    ```

    When `JSON_USE_IMPLICIT_CONVERSIONS` is defined to `0`, the code above does no longer compile. Instead, it must be
    written like this:

    ```cpp
    json j = "Hello, world!";
    auto s = j.get<std::string>();
    ```

## Version history

- Added in version 3.9.0.
