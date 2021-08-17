# Supported Macros

Some aspects of the library can be configured by defining preprocessor macros before including the `json.hpp` header.

## `JSON_ASSERT(x)`

The default value is `#!cpp assert(x)`.

## `JSON_CATCH_USER(exception)`

This macro overrides `#!cpp catch` calls inside the library. The argument is the type of the exception to catch. As of version 3.8.0, the library only catches `std::out_of_range` exceptions internally to rethrow them as [`json::out_of_range`](../home/exceptions.md#out-of-range) exceptions. The macro is always followed by a scope.

See [Switch off exceptions](../home/exceptions.md#switch-off-exceptions) for an example.

## `JSON_DIAGNOSTICS`

This macro enables extended diagnostics for exception messages. Possible values are `1` to enable or `0` to disable (default).

When enabled, exception messages contain a [JSON Pointer](json_pointer.md) to the JSON value that triggered the exception, see [Extended diagnostic messages](../home/exceptions.md#extended-diagnostic-messages) for an example. Note that enabling this macro increases the size of every JSON value by one pointer and adds some runtime overhead.

The diagnostics messages can also be controlled with the CMake option `JSON_Diagnostics` (`OFF` by default) which sets `JSON_DIAGNOSTICS` accordingly.

## `JSON_HAS_CPP_11`, `JSON_HAS_CPP_14`, `JSON_HAS_CPP_17`, `JSON_HAS_CPP_20`

The library targets C++11, but also supports some features introduced in later C++ versions (e.g., `std::string_view` support for C++17). For these new features, the library implements some preprocessor checks to determine the C++ standard. By defining any of these symbols, the internal check is overridden and the provided C++ version is unconditionally assumed. This can be helpful for compilers that only implement parts of the standard and would be detected incorrectly.

## `JSON_NOEXCEPTION`

Exceptions can be switched off by defining the symbol `JSON_NOEXCEPTION`.
When defining `JSON_NOEXCEPTION`, `#!cpp try` is replaced by `#!cpp if (true)`, 
`#!cpp catch` is replaced by `#!cpp if (false)`, and `#!cpp throw` is replaced by `#!cpp std::abort()`.

The same effect is achieved by setting the compiler flag `-fno-exceptions`.

Note the explanatory [`what()`](https://en.cppreference.com/w/cpp/error/exception/what) string of exceptions is not available for MSVC if exceptions are disabled, see [#2824](https://github.com/nlohmann/json/discussions/2824).

## `JSON_NO_IO`

When defined, headers `<cstdio>`, `<ios>`, `<iosfwd>`, `<istream>`, and `<ostream>` are not included and parse functions relying on these headers are excluded. This is relevant for environment where these I/O functions are disallowed for security reasons (e.g., Intel Software Guard Extensions (SGX)).

## `JSON_SKIP_UNSUPPORTED_COMPILER_CHECK`

When defined, the library will not create a compile error when a known unsupported compiler is detected. This allows to use the library with compilers that do not fully support C++11 and may only work if unsupported features are not used.

## `JSON_THROW_USER(exception)`

This macro overrides `#!cpp throw` calls inside the library. The argument is the exception to be thrown. Note that `JSON_THROW_USER` should leave the current scope (e.g., by throwing or aborting), as continuing after it may yield undefined behavior.

See [Switch off exceptions](../home/exceptions.md#switch-off-exceptions) for an example.

## `JSON_TRY_USER`

This macro overrides `#!cpp try` calls inside the library. It has no arguments and is always followed by a scope.

See [Switch off exceptions](../home/exceptions.md#switch-off-exceptions) for an example.

## `JSON_USE_IMPLICIT_CONVERSIONS`

When defined to `0`, implicit conversions are switched off. By default, implicit conversions are switched on.

??? example

    This is an example for an implicit conversion:
    
    ```cpp
    json j = "Hello, world!";
    std::string s = j;
    ```
    
    When `JSON_USE_IMPLICIT_CONVERSIONS` is defined to `0`, the code above does no longer compile. Instead, it must be written like this:

    ```cpp
    json j = "Hello, world!";
    auto s = j.get<std::string>();
    ```

Implicit conversions can also be controlled with the CMake option `JSON_ImplicitConversions` (`ON` by default) which sets `JSON_USE_IMPLICIT_CONVERSIONS` accordingly.

## `NLOHMANN_DEFINE_TYPE_INTRUSIVE(type, member...)`

This macro can be used to simplify the serialization/deserialization of types if (1) want to use a JSON object as serialization and (2) want to use the member variable names as object keys in that object.

The macro is to be defined inside of the class/struct to create code for. Unlike [`NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE`](#nlohmann_define_type_non_intrusivetype-member), it can access private members.
The first parameter is the name of the class/struct, and all remaining parameters name the members.

See [Simplify your life with macros](arbitrary_types.md#simplify-your-life-with-macros) for an example.

## `NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(type, member...)`

This macro can be used to simplify the serialization/deserialization of types if (1) want to use a JSON object as serialization and (2) want to use the member variable names as object keys in that object.

The macro is to be defined inside of the namespace of the class/struct to create code for. Private members cannot be accessed. Use [`NLOHMANN_DEFINE_TYPE_INTRUSIVE`](#nlohmann_define_type_intrusivetype-member) in these scenarios.
The first parameter is the name of the class/struct, and all remaining parameters name the members.

See [Simplify your life with macros](arbitrary_types.md#simplify-your-life-with-macros) for an example.

## `NLOHMANN_JSON_SERIALIZE_ENUM(type, ...)`

This macro simplifies the serialization/deserialization of enum types. See [Specializing enum conversion](enum_conversion.md) for more information.
