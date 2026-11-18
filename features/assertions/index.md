# Runtime Assertions

The code contains numerous debug assertions to ensure class invariants are valid or to detect undefined behavior. Whereas the former class invariants are nothing to be concerned with, the latter checks for undefined behavior are to detect bugs in client code.

## Switch off runtime assertions

Runtime assertions can be switched off by defining the preprocessor macro `NDEBUG` (see the [documentation of assert](https://en.cppreference.com/w/cpp/error/assert)) which is the default for release builds. Without `NDEBUG`, the assertions are compiled in and contain the name of the source file (`__FILE__`); see [notes for builds and distribution](https://json.nlohmann.me/integration/#notes-for-builds-and-distribution) if that path must not end up in your binaries.

## Change assertion behavior

The behavior of runtime assertions can be changed by defining macro [`JSON_ASSERT(x)`](https://json.nlohmann.me/api/macros/json_assert/index.md) before including the `json.hpp` header.

## Function with runtime assertions

The examples below identify the failing assertion and the function containing it. The exact diagnostic format, source filename, and line number depend on the platform, library version, and whether the single-header or multi-header version is used.

### Unchecked access to a const value

Function [`operator[]`](https://json.nlohmann.me/api/basic_json/operator%5B%5D/index.md) implements unchecked access for arrays and objects. Whereas a missing element is added in the case of non-const values, accessing a const value with a missing object key or an invalid array index is undefined behavior (think of a dereferenced null pointer) and yields a runtime assertion. This also applies to a [JSON pointer](https://json.nlohmann.me/features/json_pointer/index.md) that refers to a missing key or an invalid index.

If you are not sure whether an element exists, use checked access with the [`at` function](https://json.nlohmann.me/api/basic_json/at/index.md) or call the [`contains` function](https://json.nlohmann.me/api/basic_json/contains/index.md) before.

See also the documentation on [element access](https://json.nlohmann.me/features/element_access/index.md).

Example: missing object key

The following code will trigger an assertion at runtime:

```
#include <nlohmann/json.hpp>

using nlohmann::json;

int main()
{
    const json j = {{"key", "value"}};
    auto v = j["missing"];
}
```

The assertion `it != m_data.m_value.object->end()` fails in `operator[]`.

Example 2: Invalid array index in a JSON pointer

The following code will trigger an assertion at runtime:

```
#include <nlohmann/json.hpp>

using nlohmann::json;
using namespace nlohmann::literals;

int main()
{
    const json j = {{"array", {1, 2, 3}}};
    auto v = j["/array/5"_json_pointer];
}
```

The assertion `idx < ptr->m_data.m_value.array->size()` fails in `get_unchecked`.

### Constructing from an uninitialized iterator range

Constructing a JSON value from an iterator range (see [constructor](https://json.nlohmann.me/api/basic_json/basic_json/index.md)) with an uninitialized iterator is undefined behavior and yields a runtime assertion.

Example: uninitialized iterator range

The following code will trigger an assertion at runtime:

```
#include <nlohmann/json.hpp>

using nlohmann::json;

int main()
{
    json::iterator it1, it2;
    json j(it1, it2);
}
```

The assertion `first.m_object != nullptr` fails in `basic_json`.

### Operations on uninitialized iterators

Any operation on uninitialized iterators (i.e., iterators that are not associated with any JSON value) is undefined behavior and yields a runtime assertion.

Example: uninitialized iterator

The following code will trigger an assertion at runtime:

```
#include <nlohmann/json.hpp>

using nlohmann::json;

int main()
{
  json::iterator it;
  ++it;
}
```

The assertion `m_object != nullptr` fails in `operator++`.

## Changes

### Reading from a null `FILE` or `char` pointer

Reading from a null `FILE` or `char` pointer in C++ is undefined behavior. Until version 3.12.0, this library asserted that the pointer was not `nullptr` using a runtime assertion. If assertions were disabled, this would result in undefined behavior. Since version 3.12.0, this library checks for `nullptr` and throws a [`parse_error.101`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error101) to prevent the undefined behavior.

Example: reading from null pointer

The following code will trigger an assertion at runtime:

```
#include <iostream>
#include <nlohmann/json.hpp>

using nlohmann::json;

int main()
{
    std::FILE* f = std::fopen("nonexistent_file.json", "r");
    try {
        json j = json::parse(f);
    } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }
}
```

Output:

```
[json.exception.parse_error.101] parse error: attempting to parse an empty input; check that your input string or stream contains the expected JSON
```

## See also

- [`JSON_ASSERT`](https://json.nlohmann.me/api/macros/json_assert/index.md) - control behavior of runtime assertions
- [Supported Macros](https://json.nlohmann.me/features/macros/index.md) - all supported macros
- [Working Without Exceptions](https://json.nlohmann.me/features/no_exceptions/index.md) - using the library without exceptions
- [Exceptions](https://json.nlohmann.me/home/exceptions/index.md) - all exceptions and their error codes
- [Macros](https://json.nlohmann.me/api/macros/index.md) - reference of all macros
