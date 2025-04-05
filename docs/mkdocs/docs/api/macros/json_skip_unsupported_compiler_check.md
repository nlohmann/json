# JSON_SKIP_UNSUPPORTED_COMPILER_CHECK

```cpp
#define JSON_SKIP_UNSUPPORTED_COMPILER_CHECK
```

When defined, the library will not create a compile error when a known unsupported compiler is detected. This allows 
using the library with compilers that do not fully support C++11 and may only work if unsupported features are not used.

## Default definition

By default, the macro is not defined.

```cpp
#undef JSON_SKIP_UNSUPPORTED_COMPILER_CHECK
```

## Examples

??? example

    The code below switches off the check whether the compiler is supported.

    ```cpp
    #define JSON_SKIP_UNSUPPORTED_COMPILER_CHECK 1
    #include <nlohmann/json.hpp>

    ...
    ```

## Version history

Added in version 3.2.0.
