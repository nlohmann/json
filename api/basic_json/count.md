# <small>nlohmann::basic_json::</small>count

```cpp
// (1)
size_type count(const typename object_t::key_type& key) const;

// (2)
template<typename KeyType>
size_type count(KeyType&& key) const;

// (3)
template<typename T>
size_type count(T) const = delete;
```

1. Returns the number of elements with key `key`. If `ObjectType` is the default `std::map` type, the return value will
   always be `0` (`key` was not found) or `1` (`key` was found).
2. See 1. This overload is only available if `KeyType` is comparable with `#!cpp typename object_t::key_type` and
   `#!cpp typename object_comparator_t::is_transparent` denotes a type.
3. Deleted: this overload is only available if `T` is an integral type and is declared as deleted, so that a call with
   an integer `key` (for example, `#!cpp j.count(0)`) fails to compile. Otherwise, the integer literal `0` would convert to
   a null `#!cpp const char*` and, from there, to the key type, causing undefined behavior at runtime.

## Template parameters

`KeyType`
:   A type for an object key other than [`json_pointer`](../json_pointer/index.md) that is comparable with
    [`string_t`](string_t.md) using  [`object_comparator_t`](object_comparator_t.md).
    This can also be a string view (C++17).

## Parameters

`key` (in)
:   key value of the element to count.
    
## Return value

Number of elements with key `key`. If the JSON value is not an object, the return value will be `0`.

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Complexity

Logarithmic in the size of the JSON object.

## Notes

- This method always returns `0` when executed on a JSON type that is not an object.
- Calling this function with an integer argument (for example, `#!cpp count(0)`) does not compile: such an argument
  would otherwise implicitly convert to a null `#!cpp const char*` and, from there, cause undefined behavior when
  constructing a `#!cpp std::string` for the object key. To check for an array element instead, use [`at`](at.md),
  [`operator[]`](operator%5B%5D.md), or compare against [`size`](size.md).

## Examples

??? example "Example: (1) count number of elements"

    The example shows how `count()` is used.
    
    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
    int main()
    {
        // create a JSON object
        json j_object = {{"one", 1}, {"two", 2}};
    
        // call count()
        auto count_two = j_object.count("two");
        auto count_three = j_object.count("three");
    
        // print values
        std::cout << "number of elements with key \"two\": " << count_two << '\n';
        std::cout << "number of elements with key \"three\": " << count_three << '\n';
    }
    
    ```
    
    Output:
    
    ```json
    number of elements with key "two": 1
    number of elements with key "three": 0
    
    ```

??? example "Example: (2) count number of elements using string_view"

    The example shows how `count()` is used.
    
    ```cpp
    #include <iostream>
    #include <string_view>
    #include <nlohmann/json.hpp>
    
    using namespace std::string_view_literals;
    using nlohmann::json;
    
    int main()
    {
        // create a JSON object
        json j_object = {{"one", 1}, {"two", 2}};
    
        // call count()
        auto count_two = j_object.count("two"sv);
        auto count_three = j_object.count("three"sv);
    
        // print values
        std::cout << "number of elements with key \"two\": " << count_two << '\n';
        std::cout << "number of elements with key \"three\": " << count_three << '\n';
    }
    
    ```
    
    Output:
    
    ```json
    number of elements with key "two": 1
    number of elements with key "three": 0
    
    ```

## See also

- [find](find.md) find a value in an object
- [contains](contains.md) checks whether a key exists
- [basic_json_view::count](../basic_json_view/count.md) - the same check on a zero-copy view

## Version history

1. Added in version 3.11.0.
2. Added in version 1.0.0. Changed to support comparable key types in version 3.11.0. Support for keys convertible to
   `std::string_view` added in version 3.13.0, consistently across the lookup functions.
3. Deleted overload for integral key types added in version 3.13.0 to reject such calls at compile time instead of
   causing undefined behavior at runtime.
