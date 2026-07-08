# JSON_CATCH_USER, JSON_THROW_USER, JSON_TRY_USER

```
// (1)
#define JSON_CATCH_USER(exception) /* value */
// (2)
#define JSON_THROW_USER(exception) /* value */
// (3)
#define JSON_TRY_USER /* value */
```

Controls how exceptions are handled by the library.

1. This macro overrides [`catch`](https://en.cppreference.com/w/cpp/language/try_catch) calls inside the library. The argument is the type of the exception to catch. As of version 3.8.0, the library only catches `std::out_of_range` exceptions internally to rethrow them as [`json::out_of_range`](https://json.nlohmann.me/home/exceptions/#out-of-range) exceptions. The macro is always followed by a scope.
1. This macro overrides `throw` calls inside the library. The argument is the exception to be thrown. Note that `JSON_THROW_USER` should leave the current scope (e.g., by throwing or aborting), as continuing after it may yield undefined behavior.
1. This macro overrides `try` calls inside the library. It has no arguments and is always followed by a scope.

## Parameters

`exception` (in) : an exception type

## Default definition

By default, the macros map to their respective C++ keywords:

```
#define JSON_CATCH_USER(exception) catch(exception)
#define JSON_THROW_USER(exception) throw exception
#define JSON_TRY_USER              try
```

When exceptions are switched off, the `try` block is executed unconditionally, and throwing exceptions is replaced by calling [`std::abort`](https://en.cppreference.com/w/cpp/utility/program/abort) to make reaching the `throw` branch abort the process.

```
#define JSON_THROW_USER(exception) std::abort()
#define JSON_TRY_USER              if (true)
#define JSON_CATCH_USER(exception) if (false)
```

## Examples

Example

The code below switches off exceptions and creates a log entry with a detailed error message in case of errors.

```
#include <iostream>

#define JSON_TRY_USER if(true)
#define JSON_CATCH_USER(exception) if(false)
#define JSON_THROW_USER(exception)                           \
    {std::clog << "Error in " << __FILE__ << ":" << __LINE__ \
               << " (function " << __FUNCTION__ << ") - "    \
               << (exception).what() << std::endl;           \
     std::abort();}

#include <nlohmann/json.hpp>
```

## See also

- [Switch off exceptions](https://json.nlohmann.me/home/exceptions/#switch-off-exceptions) for more information how to switch off exceptions
- [JSON_NOEXCEPTION](https://json.nlohmann.me/api/macros/json_noexception/index.md) - switch off exceptions

## Version history

- Added in version 3.1.0.
