# JSON_ASSERT

```
#define JSON_ASSERT(x) /* value */
```

This macro controls which code is executed for [runtime assertions](https://json.nlohmann.me/features/assertions/index.md) of the library.

## Parameters

`x` (in) : expression of a scalar type

## Default definition

The default value is [`assert(x)`](https://en.cppreference.com/w/cpp/error/assert).

```
#define JSON_ASSERT(x) assert(x)
```

Therefore, assertions can be switched off by defining `NDEBUG`.

## Notes

- The library uses numerous assertions to guarantee invariants and to abort in case of otherwise undefined behavior (e.g., when calling [operator[]](https://json.nlohmann.me/api/basic_json/operator%5B%5D/index.md) with a missing object key on a `const` object). See page [runtime assertions](https://json.nlohmann.me/features/assertions/index.md) for more information.
- Defining the macro to code that does not call `std::abort` may leave the library in an undefined state.
- The macro is undefined outside the library.

## Examples

Example 1: default behavior

The following code will trigger an assertion at runtime:

```
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    const json j = {{"key", "value"}};
    auto v = j["missing"];
}
```

Output:

```
Assertion failed: (m_value.object->find(key) != m_value.object->end()), function operator[], file json.hpp, line 2144.
```

Example 2: user-defined behavior

The assertion reporting can be changed by defining `JSON_ASSERT(x)` differently.

```
#include <cstdio>
#include <cstdlib>
#define JSON_ASSERT(x) if(!(x)){fprintf(stderr, "assertion error in %s\n", __FUNCTION__); std::abort();}

#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    const json j = {{"key", "value"}};
    auto v = j["missing"];
}
```

Output:

```
assertion error in operator[]
```

## See also

- [Runtime Assertions](https://json.nlohmann.me/features/assertions/index.md) - overview documentation

## Version history

- Added in version 3.9.0.
