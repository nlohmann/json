# JSON_BRACE_INIT_COPY_SEMANTICS

```cpp
#define JSON_BRACE_INIT_COPY_SEMANTICS /* value */
```

When defined to `1`, single-element brace initialization of a `basic_json` value is treated as a copy/move of the
element rather than wrapping it in a single-element array.

## Default definition

The default value is `0` (disabled — existing behavior is preserved).

```cpp
#define JSON_BRACE_INIT_COPY_SEMANTICS 0
```

## Notes

!!! note "Background"

    C++ always prefers the `initializer_list` constructor over the copy/move constructor for brace initialization. This
    means that code like

    ```cpp
    json obj = {{"key", "value"}};
    json j{obj};
    ```

    creates a single-element **array** `[{"key":"value"}]` instead of a copy of `obj`. This behavior is
    compiler-dependent for older compilers (GCC wrapped, Clang did not), but starting from Clang 20, both compilers
    behave the same way.

    Enabling this macro opts into copy/move semantics for this case
    (see [#5074](https://github.com/nlohmann/json/issues/5074)).

!!! warning "Opt-in only"

    This macro must be defined **before** including `<nlohmann/json.hpp>`. Defining it after the include has no effect.

!!! tip "Workaround without the macro"

    To explicitly create a single-element array without enabling this macro, use `json::array()`:

    ```cpp
    json j = json::array({obj});  // always creates [obj]
    ```

## Examples

??? example "Default behavior (macro not defined)"

    Without the macro, single-element brace initialization wraps the value in an array:

    ```cpp
    #include <nlohmann/json.hpp>

    using json = nlohmann::json;

    int main()
    {
        json obj = {{"key", "value"}};

        json j{obj};
        // j is [{"key":"value"}]  -- single-element array, NOT a copy of obj
    }
    ```

??? example "Opt-in copy semantics (macro defined to 1)"

    With the macro, single-element brace initialization copies/moves the value:

    ```cpp
    #define JSON_BRACE_INIT_COPY_SEMANTICS 1
    #include <nlohmann/json.hpp>

    using json = nlohmann::json;

    int main()
    {
        json obj = {{"key", "value"}};

        json j{obj};
        // j is {"key":"value"}  -- copy of obj
    }
    ```

## See also

- [FAQ: Brace initialization yields arrays](../../home/faq.md#brace-initialization-yields-arrays)
- [**basic_json(initializer_list_t)**](../basic_json/basic_json.md) - the affected constructor

## Version history

- Added in version 3.12.0.
