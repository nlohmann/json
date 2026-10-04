# <small>nlohmann::basic_json::</small>contains

```cpp
// (1)
bool contains(const typename object_t::key_type& key) const;

// (2)
template<typename KeyType>
bool contains(KeyType&& key) const;

// (3)
bool contains(const json_pointer& ptr) const;
```

1. Check whether an element exists in a JSON object with a key equivalent to `key`. If the element is not found or the 
   JSON value is not an object, `#!cpp false` is returned.
2. See 1. This overload is only available if `KeyType` is comparable with `#!cpp typename object_t::key_type` and
   `#!cpp typename object_comparator_t::is_transparent` denotes a type.
3. Check whether the given JSON pointer `ptr` can be resolved in the current JSON value.

## Template parameters

`KeyType`
:   A type for an object key other than [`json_pointer`](../json_pointer/index.md) that is comparable with
    [`string_t`](string_t.md) using  [`object_comparator_t`](object_comparator_t.md).
    This can also be a string view (C++17).

## Parameters

`key` (in)
:   key value to check its existence.

`ptr` (in)
:   JSON pointer to check its existence.

## Return value

1. `#!cpp true` if an element with specified `key` exists. If no such element with such a key is found or the JSON value
   is not an object, `#!cpp false` is returned.
2. See 1.
3. `#!cpp true` if the JSON pointer can be resolved to a stored value, `#!cpp false` otherwise.

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Exceptions

1. The function does not throw exceptions.
2. The function does not throw exceptions.
3. The function does not throw exceptions.

## Complexity

Logarithmic in the size of the JSON object.

## Notes

- This method always returns `#!cpp false` when executed on a JSON type that is not an object.
- This method can be executed on any JSON value type.
- Calling this function with an integer argument (for example, `#!cpp contains(0)`) does not compile: such an argument
  would otherwise implicitly convert to a null `#!cpp const char*` and, from there, cause undefined behavior when
  constructing a `#!cpp std::string` for the object key. To check for an array element instead, use [`at`](at.md),
  [`operator[]`](operator%5B%5D.md), or compare against [`size`](size.md).

!!! info "Postconditions"

    If `#!cpp j.contains(x)` returns `#!c true` for a key or JSON pointer `x`, then it is safe to call `j[x]`.

!!! warning "Deprecation"

    Overload (3) also accepts a [`json_pointer`](../json_pointer/index.md) whose template argument is a `basic_json`
    specialization (e.g., `nlohmann::json_pointer<nlohmann::json>`) instead of a string type. This is deprecated since
    version 3.11.0 and will be removed in a future major version; use `basic_json::json_pointer` (for `json`,
    `nlohmann::json_pointer<std::string>`) instead.

    You should be warned by your compiler with a `-Wdeprecated-declarations` warning if you are using a deprecated
    function.

    See the [migration guide](../../integration/migration_guide.md#json-pointers) for how to update existing code.

## Examples

??? example "Example: (1) check with key"

    The example shows how `contains()` is used.
    
    ```cpp
    --8<-- "examples/contains__object_t_key_type.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/contains__object_t_key_type.output"
    ```

??? example "Example: (2) check with key using string_view"

    The example shows how `contains()` is used.
    
    ```cpp
    --8<-- "examples/contains__keytype.c++17.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/contains__keytype.c++17.output"
    ```

??? example "Example: (3) check with JSON pointer"

    The example shows how `contains()` is used.
    
    ```cpp
    --8<-- "examples/contains__json_pointer.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/contains__json_pointer.output"
    ```

## See also

- [find](find.md) find a value in an object
- [count](count.md) returns the number of occurrences of a key

## Version history

1. Added in version 3.11.0.
2. Added in version 3.6.0. Extended template `KeyType` to support comparable types in version 3.11.0. Fixed in
   version 3.13.0 to consistently accept `std::string_view`-convertible keys, as already supported by
   [`operator[]`](operator[].md), [`at`](at.md), [`value`](value.md), and other lookup functions.
3. Added in version 3.7.0.
4. Deleted overloads for integral key types added in version 3.13.0 to reject such calls at compile time instead of
   causing undefined behavior at runtime.
