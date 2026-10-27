# JSON_NOEXCEPTION

```
#define JSON_NOEXCEPTION
```

Exceptions can be switched off by defining the symbol `JSON_NOEXCEPTION`. When defining `JSON_NOEXCEPTION`, `try` is replaced by `if (true)`, `catch` is replaced by `if (false)`, and `throw` is replaced by `std::abort()`.

The same effect is achieved by setting the compiler flag `-fno-exceptions`.

## Default definition

By default, the macro is not defined.

```
#undef JSON_NOEXCEPTION
```

## Notes

The explanatory [`what()`](https://en.cppreference.com/w/cpp/error/exception/what) string of exceptions is not available for MSVC if exceptions are disabled, see [#2824](https://github.com/nlohmann/json/discussions/2824).

## Examples

Example

The code below switches off exceptions in the library.

```
#define JSON_NOEXCEPTION 1
#include <nlohmann/json.hpp>

...
```

## See also

- [Switch off exceptions](https://json.nlohmann.me/home/exceptions/#switch-off-exceptions) - more information how to switch off exceptions
- [Supported Macros](https://json.nlohmann.me/features/macros/index.md) - guide to all supported macros
- [Working Without Exceptions](https://json.nlohmann.me/features/no_exceptions/index.md) - using the library without exceptions
- [Exceptions](https://json.nlohmann.me/home/exceptions/index.md) - all exceptions and their error codes
- [`exception`](https://json.nlohmann.me/api/basic_json/exception/index.md) - base class of all exceptions thrown by the library

## Version history

Added in version 2.1.0.
