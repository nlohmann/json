# Runtime Assertions

The code contains numerous debug assertions to ensure class invariants are valid or to detect undefined behavior.
Whereas the former class invariants are nothing to be concerned with, the latter checks for undefined behavior are to
detect bugs in client code.

## Switch off runtime assertions

Runtime assertions can be switched off by defining the preprocessor macro `NDEBUG` (see the
[documentation of assert](https://en.cppreference.com/w/cpp/error/assert)) which is the default for release builds.

## Change assertion behavior

The behavior of runtime assertions can be changed by defining macro [`JSON_ASSERT(x)`](../api/macros/json_assert.md)
before including the `json.hpp` header.

## Function with runtime assertions

### Unchecked access to a const value

Function [`operator[]`](../api/basic_json/operator%5B%5D.md) implements unchecked access for arrays and objects. Whereas
a missing element is added in the case of non-const values, accessing a const value with a missing object key or an
invalid array index is undefined behavior (think of a dereferenced null pointer) and yields a runtime assertion. This
also applies to a [JSON pointer](json_pointer.md) that refers to a missing key or an invalid index.

If you are not sure whether an element exists, use checked access with the [`at` function](../api/basic_json/at.md)
or call the [`contains` function](../api/basic_json/contains.md) before.

See also the documentation on [element access](element_access/index.md).

??? example "Example: missing object key"

    The following code will trigger an assertion at runtime:

    ```cpp
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
    Assertion failed: (it != m_data.m_value.object->end()), function operator[], file json.hpp, line 28795.
    ```

??? example "Example 2: Invalid array index in a JSON pointer"

    The following code will trigger an assertion at runtime:

    ```cpp
    #include <nlohmann/json.hpp>
    
    using json = nlohmann::json;
    using namespace nlohmann::literals;
    
    int main()
    {
        const json j = {{"array", {1, 2, 3}}};
        auto v = j["/array/5"_json_pointer];
    }
    ```

    Output:

    ```
    Assertion failed: (idx < m_data.m_value.array->size()), function operator[], file json.hpp, line 28758.
    ```

### Constructing from an uninitialized iterator range

Constructing a JSON value from an iterator range (see [constructor](../api/basic_json/basic_json.md)) with an
uninitialized iterator is undefined behavior and yields a runtime assertion.

??? example "Example: uninitialized iterator range"

    The following code will trigger an assertion at runtime:

    ```cpp
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

Any operation on uninitialized iterators (i.e., iterators that are not associated with any JSON value) is undefined
behavior and yields a runtime assertion.

??? example "Example: uninitialized iterator"

    The following code will trigger an assertion at runtime:

    ```cpp
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

Reading from a null `#!cpp FILE` or `#!cpp char` pointer in C++ is undefined behavior.  Until version 3.12.0, this
library asserted that the pointer was not `nullptr` using a runtime assertion. If assertions were disabled, this would
result in undefined behavior. Since version 3.12.0, this library checks for `nullptr` and throws a
[`parse_error.101`](../home/exceptions.md#jsonexceptionparse_error101) to prevent the undefined behavior.

??? example "Example: reading from null pointer"

    The following code will trigger an assertion at runtime:

    ```cpp
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

- [JSON_ASSERT](../api/macros/json_assert.md) - control behavior of runtime assertions
