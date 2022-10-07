# <small>nlohmann::basic_json::</small>value

```cpp
// (1)
template<class ValueType>
ValueType value(const typename object_t::key_type& key,
                ValueType&& default_value) const;

// (2)
template<class ValueType, class KeyType>
ValueType value(KeyType&& key,
                ValueType&& default_value) const;

// (3)
template<class ValueType>
ValueType value(const json_pointer& ptr,
                const ValueType& default_value) const;
```

1. Returns either a copy of an object's element at the specified key `key` or a given default value if no element with
   key `key` exists.
   
    The function is basically equivalent to executing
    ```cpp
    try {
       return at(key);
    } catch(out_of_range) {
       return default_value;
    }
    ```

2. See 1. This overload is only available if `KeyType` is comparable with `#!cpp typename object_t::key_type` and
   `#!cpp typename object_comparator_t::is_transparent` denotes a type.

3. Returns either a copy of an object's element at the specified JSON pointer `ptr` or a given default value if no value
   at `ptr` exists.
   
    The function is basically equivalent to executing
    ```cpp
    try {
       return at(ptr);
    } catch(out_of_range) {
       return default_value;
    }
    ```

!!! note "Differences to `at` and `operator[]`"

    - Unlike [`at`](at.md), this function does not throw if the given `key`/`ptr` was not found.
    - Unlike [`operator[]`](operator[].md), this function does not implicitly add an element to the position defined by
     `key`/`ptr` key. This function is furthermore also applicable to const objects.

## Template parameters

`KeyType`
:   A type for an object key other than [`json_pointer`](../json_pointer/index.md) that is comparable with
    [`string_t`](string_t.md) using  [`object_comparator_t`](object_comparator_t.md).
    This can also be a string view (C++17).
`ValueType` 
:   type compatible to JSON values, for instance `#!cpp int` for JSON integer numbers, `#!cpp bool` for JSON booleans,
    or `#!cpp std::vector` types for JSON arrays. Note the type of the expected value at `key`/`ptr` and the default
    value `default_value` must be compatible.

## Parameters

`key` (in)
:   key of the element to access

`default_value` (in)
:   the value to return if `key`/`ptr` found no value

`ptr` (in)
:   a JSON pointer to the element to access

## Return value

1. copy of the element at key `key` or `default_value` if `key` is not found
2. copy of the element at key `key` or `default_value` if `key` is not found
3. copy of the element at JSON Pointer `ptr` or `default_value` if no value for `ptr` is found

## Exception safety

Strong guarantee: if an exception is thrown, there are no
changes to any JSON value.

## Exceptions

1. The function can throw the following exceptions:
    - Throws [`type_error.302`](../../home/exceptions.md#jsonexceptiontype_error302) if `default_value` does not match
      the type of the value at `key`
    - Throws [`type_error.306`](../../home/exceptions.md#jsonexceptiontype_error306) if the JSON value is not an object;
      in that case, using `value()` with a key makes no sense.
2. See 1.
3. The function can throw the following exceptions:
    - Throws [`type_error.302`](../../home/exceptions.md#jsonexceptiontype_error302) if `default_value` does not match
      the type of the value at `ptr`
    - Throws [`type_error.306`](../../home/exceptions.md#jsonexceptiontype_error306) if the JSON value is not an object;
      in that case, using `value()` with a key makes no sense.

## Complexity

1. Logarithmic in the size of the container.
2. Logarithmic in the size of the container.
3. Logarithmic in the size of the container.

## Examples

??? example "Example: (1) access specified object element with default value"

    The example below shows how object elements can be queried with a default value.
    
    ```cpp
    --8<-- "examples/value__object_t_key_type.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/value__object_t_key_type.output"
    ```

??? example "Example: (2) access specified object element using string_view with default value"

    The example below shows how object elements can be queried with a default value.
    
    ```cpp
    --8<-- "examples/value__keytype.c++17.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/value__keytype.c++17.output"
    ```

??? example "Example: (3) access specified object element via JSON Pointer with default value"

    The example below shows how object elements can be queried with a default value.
    
    ```cpp
    --8<-- "examples/value__json_ptr.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/value__json_ptr.output"
    ```

## See also

- see [`at`](at.md) for access by reference with range checking
- see [`operator[]`](operator%5B%5D.md) for unchecked access by reference

## Version history

1. Added in version 1.0.0. Changed parameter `default_value` type from `const ValueType&` to `ValueType&&` in version 3.11.0.
2. Added in version 3.11.0. Made `ValueType` the first template parameter in version 3.11.2.
3. Added in version 2.0.2.
