# Runtime Assertions

The code contains numerous debug assertions to ensure class invariants are valid or to detect undefined behavior. Whereas the former class invariants are nothing to be concerned with, the latter checks for undefined behavior are to detect bugs in client code.

## Switch off runtime assertions

Runtime assertions can be switched off by defining the preprocessor macro `NDEBUG` (see the [documentation of assert](https://en.cppreference.com/w/cpp/error/assert)) which is the default for release builds.

## Change assertion behavior

The behavior of runtime assertions can be changed by defining macro [`JSON_ASSERT(x)`](https://json.nlohmann.me/api/macros/json_assert/index.md) before including the `json.hpp` header.

## Function with runtime assertions

### Unchecked object access to a const value

Function [`operator[]`](https://json.nlohmann.me/api/basic_json/operator%5B%5D/index.md) implements unchecked access for objects. Whereas a missing key is added in the case of non-const objects, accessing a const object with a missing key is undefined behavior (think of a dereferenced null pointer) and yields a runtime assertion.

If you are not sure whether an element in an object exists, use checked access with the [`at` function](https://json.nlohmann.me/api/basic_json/at/index.md) or call the [`contains` function](https://json.nlohmann.me/api/basic_json/contains/index.md) before.

See also the documentation on [element access](https://json.nlohmann.me/features/element_access/index.md).

Example 1: Missing object key

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

### Constructing from an uninitialized iterator range

Constructing a JSON value from an iterator range (see [constructor](https://json.nlohmann.me/api/basic_json/basic_json/index.md)) with an uninitialized iterator is undefined behavior and yields a runtime assertion.

Example 2: Uninitialized iterator range

The following code will trigger an assertion at runtime:

```
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    json::iterator it1, it2;
    json j(it1, it2);
}
```

Output:

```
Assertion failed: (m_object != nullptr), function operator++, file iter_impl.hpp, line 368.
```

### Operations on uninitialized iterators

Any operation on uninitialized iterators (i.e., iterators that are not associated with any JSON value) is undefined behavior and yields a runtime assertion.

Example 3: Uninitialized iterator

The following code will trigger an assertion at runtime:

```
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
  json::iterator it;
  ++it;
}
```

Output:

```
Assertion failed: (m_object != nullptr), function operator++, file iter_impl.hpp, line 368.
```

## Changes

### Reading from a null `FILE` or `char` pointer

Reading from a null `FILE` or `char` pointer in C++ is undefined behavior. Until version 3.12.0, this library asserted that the pointer was not `nullptr` using a runtime assertion. If assertions were disabled, this would result in undefined behavior. Since version 3.12.0, this library checks for `nullptr` and throws a [`parse_error.101`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error101) to prevent the undefined behavior.

Example 4: Reading from null pointer

The following code will trigger an assertion at runtime:

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

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

- [JSON_ASSERT](https://json.nlohmann.me/api/macros/json_assert/index.md) - control behavior of runtime assertions
