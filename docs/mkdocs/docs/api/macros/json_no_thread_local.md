# JSON_NO_THREAD_LOCAL

```cpp
#define JSON_NO_THREAD_LOCAL
```

When defined, the library does not use `#!cpp thread_local` storage. This is relevant for the few environments whose
toolchain does not support it.

The copy constructor copies the first levels of a value by copying the containers, which copy their elements, and
completes whatever is nested deeper than that without the call stack, so that copying a value cannot exhaust the stack
however deeply it is nested. It counts the levels it has descended into in a `#!cpp thread_local` variable, as a counter
shared between threads would be raced.

Without that counter, no descent can be bounded safely, so objects and arrays are copied without the call stack right
away. Copying keeps working exactly as it does otherwise - the same values come out, and deeply nested values are copied
just as safely - but copying is slower, because the containers no longer copy themselves. Copying the benchmark
documents takes 9% (`canada.json`) to 34% (`twitter.json`) longer; values built mostly from objects are affected the
most.

## Default definition

By default, `#!cpp JSON_NO_THREAD_LOCAL` is not defined.

```cpp
#undef JSON_NO_THREAD_LOCAL
```

The library defines it by itself for Clang targeting MinGW, which does not survive the `#!cpp thread_local` storage:
copying a value segfaults there, with both old and current Clang versions, while GCC targeting MinGW is unaffected.

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
