# Runtime Assertions

The code contains numerous debug assertions to ensure class invariants are valid or to detect undefined behavior.
Whereas the former class invariants are nothing to be concerned of, the latter checks for undefined behavior are to
detect bugs in client code.

## Switch off runtime assertions

Runtime assertions can be switched off by defining the preprocessor macro `NDEBUG` (see the
[documentation of assert](https://en.cppreference.com/w/cpp/error/assert)) which is the default for release builds.

## Change assertion behavior

The behavior of runtime assertions can be changes by defining macro [`JSON_ASSERT(x)`](../api/macros/json_assert.md)
before including the `json.hpp` header.

## Function with runtime assertions

### Unchecked object access to a const value

Function [`operator[]`](../api/basic_json/operator%5B%5D.md) implements unchecked access for objects. Whereas a missing
key is added in case of non-const objects, accessing a const object with a missing key is undefined behavior (think of a
dereferenced null pointer) and yields a runtime assertion.

If you are not sure whether an element in an object exists, use checked access with the
[`at` function](../api/basic_json/at.md) or call the [`contains` function](../api/basic_json/contains.md) before.

See also the documentation on [element access](element_access/index.md).

??? example "Example 1: Missing object key"

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
    Assertion failed: (m_value.object->find(key) != m_value.object->end()), function operator[], file json.hpp, line 2144.
    ```

### Constructing from an uninitialized iterator range

Constructing a JSON value from an iterator range (see [constructor](../api/basic_json/basic_json.md)) with an
uninitialized iterator is undefined behavior and yields a runtime assertion.

??? example "Example 2: Uninitialized iterator range"

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

??? example "Example 3: Uninitialized iterator"

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

Reading from a null `#!cpp FILE` or `#!cpp char` pointer in C++ is undefined behavior.  Until version 3.11.4, this
library asserted that the pointer was not `nullptr` using a runtime assertion. If assertions were disabled, this would
result in undefined behavior. Since version 3.11.4, this library checks for `nullptr` and throws a
[`parse_error.101`](../home/exceptions.md#jsonexceptionparse_error101) to prevent the undefined behavior.

??? example "Example 4: Reading from null pointer"

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
