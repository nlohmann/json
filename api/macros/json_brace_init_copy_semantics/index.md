# JSON_BRACE_INIT_COPY_SEMANTICS

```
#define JSON_BRACE_INIT_COPY_SEMANTICS /* value */
```

When defined to `1`, single-element brace initialization of a `basic_json` value is treated as a copy/move of the element rather than wrapping it in a single-element array.

## Default definition

The default value is `0` (disabled — existing behavior is preserved).

```
#define JSON_BRACE_INIT_COPY_SEMANTICS 0
```

## Notes

Background

C++ always prefers the `initializer_list` constructor over the copy/move constructor for brace initialization. This means that code like

```
json obj = {{"key", "value"}};
json j{obj};
```

creates a single-element **array** `[{"key":"value"}]` instead of a copy of `obj`. This behavior is compiler-dependent for older compilers (GCC wrapped, Clang did not), but starting from Clang 20, both compilers behave the same way.

Enabling this macro opts into copy/move semantics for this case (see [#5074](https://github.com/nlohmann/json/issues/5074)).

Opt-in only

This macro must be defined **before** including `<nlohmann/json.hpp>`. Defining it after the include has no effect.

Applies to every single-element list

The macro does not only affect a single JSON value in braces. **Any** single-element braced list is treated as its element, so it no longer creates a one-element array:

```
json j1 = {1};       // 1, not [1]
json j2 = {"text"};  // "text", not ["text"]
json j3 = {{1, 2}};  // [1,2], not [[1,2]]
```

Code that relies on these producing arrays must use `json::array()` instead (see below). Lists with more than one element, and a single `[string, value]` pair such as `{{"key", "value"}}`, which still creates an object, are not affected. The library's own conversions are not affected either: for example, `std::tuple<int>{5}` still becomes `[5]`.

ABI compatibility

The value of this macro is encoded in the [namespace](https://json.nlohmann.me/features/namespace/index.md) (tag `_bics`), resulting in distinct symbol names. Translation units compiled with and without it can therefore be linked into the same program without One Definition Rule (ODR) violations, but they cannot exchange instances of library types.

Workaround without the macro

To explicitly create a single-element array without enabling this macro, use `json::array()`:

```
json j = json::array({obj});  // always creates [obj]
```

## Examples

Default behavior (macro not defined)

Without the macro, single-element brace initialization wraps the value in an array:

```
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    json obj = {{"key", "value"}};

    json j{obj};
    // j is [{"key":"value"}]  -- single-element array, NOT a copy of obj
}
```

Opt-in copy semantics (macro defined to 1)

With the macro, single-element brace initialization copies/moves the value:

```
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

- [FAQ: Brace initialization yields arrays](https://json.nlohmann.me/home/faq/#brace-initialization-yields-arrays)
- [**basic_json(initializer_list_t)**](https://json.nlohmann.me/api/basic_json/basic_json/index.md) - the affected constructor

## Version history

- Added in version 3.13.0.
