# JSON_NOEXCEPTION

```cpp
#define JSON_NOEXCEPTION
```

Exceptions can be switched off by defining the symbol `JSON_NOEXCEPTION`. When defining `JSON_NOEXCEPTION`, `#!cpp try`
is replaced by `#!cpp if (true)`, `#!cpp catch` is replaced by `#!cpp if (false)`, and `#!cpp throw` is replaced by
`#!cpp std::abort()`.

The same effect is achieved by setting the compiler flag `-fno-exceptions`.

## Default definition

By default, the macro is not defined.

```cpp
#undef JSON_NOEXCEPTION
```

## Notes

The explanatory [`what()`](https://en.cppreference.com/w/cpp/error/exception/what) string of exceptions is not
available for MSVC if exceptions are disabled, see [#2824](https://github.com/nlohmann/json/discussions/2824).

## See also

- [Switch off exceptions](../../home/exceptions.md#switch-off-exceptions) for more information how to switch off exceptions

## Version history

Added in version 2.1.0.
