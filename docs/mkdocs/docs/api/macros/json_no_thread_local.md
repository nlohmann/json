# JSON_NO_THREAD_LOCAL

```cpp
#define JSON_NO_THREAD_LOCAL
```

When defined, the library does not use `#!cpp thread_local` storage. This is relevant for the few environments whose
toolchain does not support it.

Copying a value and comparing two values both descend into the first levels by letting the containers copy or compare
themselves, and finish whatever is nested deeper than that without the call stack, so that neither can exhaust the stack
however deeply the values are nested. Each counts the levels it has descended into in a `#!cpp thread_local` variable, as
a counter shared between threads would be raced.

Without those counters, no descent can be bounded safely, so objects and arrays are copied and compared without the call
stack right away. Both keep working exactly as they do otherwise - the same values come out, the same comparisons hold,
and deeply nested values are handled just as safely - but both are slower, because the containers no longer copy or
compare themselves. Copying the benchmark documents takes 9% (`canada.json`) to 34% (`twitter.json`) longer, and
comparing two equal ones 10% (`citm_catalog.json`) to 90% (`canada.json`) longer.

## Default definition

By default, `#!cpp JSON_NO_THREAD_LOCAL` is not defined.

```cpp
#undef JSON_NO_THREAD_LOCAL
```

The library defines it by itself for Clang targeting MinGW, which does not survive the `#!cpp thread_local` storage:
copying a value segfaults there, with both old and current Clang versions, while GCC targeting MinGW is unaffected.
Copying and comparing fall back to working without the call stack there, as they do whenever the macro is defined.

## Examples

??? example

    The code below forces the library not to use `#!cpp thread_local` storage.

    ```cpp
    #define JSON_NO_THREAD_LOCAL 1
    #include <nlohmann/json.hpp>

    ...
    ```

## Version history

- Added in version 3.12.1.
