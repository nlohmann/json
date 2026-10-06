# JSON_USE_IMPLICIT_CONVERSIONS

```
#define JSON_USE_IMPLICIT_CONVERSIONS /* value */
```

When defined to `0`, implicit conversions are switched off. By default, implicit conversions are switched on. The value directly affects [`operator ValueType`](https://json.nlohmann.me/api/basic_json/operator_ValueType/index.md) and the [converting constructor](https://json.nlohmann.me/api/basic_json/basic_json/index.md) from a `basic_json` specialization with a different string type (overload 4).

## Default definition

By default, implicit conversions are enabled.

```
#define JSON_USE_IMPLICIT_CONVERSIONS 1
```

## Notes

Future behavior change

Implicit conversions will be switched off by default in the next major release of the library.

You can prepare existing code by already defining `JSON_USE_IMPLICIT_CONVERSIONS` to `0` and replace any implicit conversions with calls to [`get`](https://json.nlohmann.me/api/basic_json/get/index.md).

See the [migration guide](https://json.nlohmann.me/integration/migration_guide/#replace-implicit-conversions) for how to update existing code.

Automatic migration

The community-maintained clang-tidy check `modernize-nlohmann-json-explicit-conversions` rewrites implicit conversions into explicit calls to [`get`](https://json.nlohmann.me/api/basic_json/get/index.md); for example, `int i = j;` becomes `int i = j.get<int>();`. The check is not part of clang-tidy itself, and it does not catch every case (for example, constructing a `std::optional` from a JSON value), so review the result. See [discussion #4610](https://github.com/nlohmann/json/discussions/4610) for how to build and use it.

CMake option

Implicit conversions can also be controlled with the CMake option [`JSON_ImplicitConversions`](https://json.nlohmann.me/integration/cmake/#json_implicitconversions) (`ON` by default) which defines `JSON_USE_IMPLICIT_CONVERSIONS` accordingly.

## Examples

Example: implicit and explicit conversions

This is an example for an implicit conversion:

```
json j = "Hello, world!";
std::string s = j;
```

When `JSON_USE_IMPLICIT_CONVERSIONS` is defined to `0`, the code above does no longer compile. Instead, it must be written like this:

```
json j = "Hello, world!";
auto s = j.get<std::string>();
```

Example: conversion between `basic_json` specializations

A `basic_json` specialization with a different string type is also no longer converted implicitly when `JSON_USE_IMPLICIT_CONVERSIONS` is defined to `0`:

```
using wjson = nlohmann::basic_json<std::map, std::vector, std::wstring>;

void load(const nlohmann::json& j);

wjson wj = /* ... */;
load(wj);                            // error: no implicit conversion
load(nlohmann::json(wj));            // OK: explicit conversion
load(wj.get<nlohmann::json>());      // OK: explicit conversion
```

Specializations that share the same string type, such as `json` and `ordered_json`, remain implicitly convertible.

## See also

- [**operator ValueType**](https://json.nlohmann.me/api/basic_json/operator_ValueType/index.md) - get a value (implicit)
- [**get**](https://json.nlohmann.me/api/basic_json/get/index.md) - get a value (explicit)
- [JSON_ImplicitConversions](https://json.nlohmann.me/integration/cmake/#json_implicitconversions) - CMake option to control the macro

## Version history

- Added in version 3.9.0.
- Also affects the conversion between `basic_json` specializations with different string types since version 3.13.0 unreleased.
