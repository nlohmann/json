# <small>nlohmann::basic_json::</small>value

```cpp
// (1)
template<class ValueType>
ValueType value(const typename object_t::key_type& key,
                const ValueType& default_value) const;

// (2)
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

2. Returns either a copy of an object's element at the specified JSON pointer `ptr` or a given default value if no value
   at `ptr` exists.
   
    The function is basically equivalent to executing
    ```cpp
    try {
       return at(ptr);
    } catch(out_of_range) {
       return default_value;
    }
    ```

!!! note

    - Unlike [`at`](at.md), this function does not throw if the given `key`/`ptr` was not found.
    - Unlike [`operator[]`](operator[].md), this function does not implicitly add an element to the position defined by
     `key`/`ptr` key. This function is furthermore also applicable to const objects.

## Template parameters

`ValueType` 
:   type compatible to JSON values, for instance `#!cpp int` for JSON integer numbers, `#!cpp bool` for JSON booleans,
    or `#!cpp std::vector` types for JSON arrays. Note the type of the expected value at `key`/`ptr` and the default
    value `default_value` must be compatible.

## Parameters

`key` (in)
:   key of the element to access

`default_value` (in)
:   the value to return if key/ptr found no value

`ptr` (in)
:   a JSON pointer to the element to access

## Return value

1. copy of the element at key `key` or `default_value` if `key` is not found
1. copy of the element at JSON Pointer `ptr` or `default_value` if no value for `ptr` is found

## Exception safety

Strong guarantee: if an exception is thrown, there are no
changes to any JSON value.

## Exceptions

1. The function can throw the following exceptions:
    - Throws [`type_error.302`](../../home/exceptions.md#jsonexceptiontype_error302) if `default_value` does not match
      the type of the value at `key`
    - Throws [`type_error.306`](../../home/exceptions.md#jsonexceptiontype_error306) if the JSON value is not an object;
      in that case, using `value()` with a key makes no sense.
2. The function can throw the following exceptions:
    - Throws [`type_error.302`](../../home/exceptions.md#jsonexceptiontype_error302) if `default_value` does not match
      the type of the value at `ptr`
    - Throws [`type_error.306`](../../home/exceptions.md#jsonexceptiontype_error306) if the JSON value is not an object;
      in that case, using `value()` with a key makes no sense.

## Complexity

1. Logarithmic in the size of the container.
2. Logarithmic in the size of the container.

## Examples

??? example "Example (1): access specified object element with default value"

    The example below shows how object elements can be queried with a default value.
    
    ```cpp
    --8<-- "examples/basic_json__value.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/basic_json__value.output"
    ```

??? example "Example (2): access specified object element via JSON Pointer with default value"

    The example below shows how object elements can be queried with a default value.
    
    ```cpp
    --8<-- "examples/basic_json__value_ptr.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/basic_json__value_ptr.output"
    ```

## See also

- see [`at`](at.md) for access by reference with range checking
- see [`operator[]`](operator%5B%5D.md) for unchecked access by reference

## Version history

1. Added in version 1.0.0.
2. Added in version 2.0.2.
