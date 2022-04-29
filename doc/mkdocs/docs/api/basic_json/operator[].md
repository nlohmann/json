# <small>nlohmann::basic_json::</small>operator[]

```cpp
// (1)
reference operator[](size_type idx);
const_reference operator[](size_type idx) const;

// (2)
reference operator[](typename object_t::key_type key);
const_reference operator[](const typename object_t::key_type& key) const;

// (3)
template<typename KeyType>
reference operator[](KeyType&& key);
template<typename KeyType>
const_reference operator[](KeyType&& key) const;

// (4)
reference operator[](const json_pointer& ptr);
const_reference operator[](const json_pointer& ptr) const;
```

1. Returns a reference to the array element at specified location `idx`.
2. Returns a reference to the object element with specified key `key`. The non-const qualified overload takes the key by value.
3. See 2. This overload is only available if `KeyType` is comparable with `#!cpp typename object_t::key_type` and
   `#!cpp typename object_comparator_t::is_transparent` denotes a type.
4. Returns a reference to the element with specified JSON pointer `ptr`.

## Template parameters

`KeyType`
:   A type for an object key other than [`json_pointer`](../json_pointer/index.md) that is comparable with
    [`string_t`](string_t.md) using  [`object_comparator_t`](object_comparator_t.md).
    This can also be a string view (C++17).

## Parameters

`idx` (in)
:   index of the element to access

`key` (in)
:   object key of the element to access
    
`ptr` (in)
:   JSON pointer to the desired element
    
## Return value

1. (const) reference to the element at index `idx`
2. (const) reference to the element at key `key`
3. (const) reference to the element at key `key`
4. (const) reference to the element pointed to by `ptr`

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Exceptions

1. The function can throw the following exceptions:
    - Throws [`type_error.305`](../../home/exceptions.md#jsonexceptiontype_error305) if the JSON value is not an array
      or null; in that case, using the `[]` operator with an index makes no sense.
2. The function can throw the following exceptions:
    - Throws [`type_error.305`](../../home/exceptions.md#jsonexceptiontype_error305) if the JSON value is not an object
      or null; in that case, using the `[]` operator with a key makes no sense.
3. See 2.
4. The function can throw the following exceptions:
    - Throws [`parse_error.106`](../../home/exceptions.md#jsonexceptionparse_error106) if an array index in the passed
      JSON pointer `ptr` begins with '0'.
    - Throws [`parse_error.109`](../../home/exceptions.md#jsonexceptionparse_error109) if an array index in the passed
      JSON pointer `ptr` is not a number.
    - Throws [`out_of_range.402`](../../home/exceptions.md#jsonexceptionout_of_range402) if the array index '-' is used
      in the passed JSON pointer `ptr` for the const version.
    - Throws [`out_of_range.404`](../../home/exceptions.md#jsonexceptionout_of_range404) if the JSON pointer `ptr` can
      not be resolved.

## Complexity

1. Constant if `idx` is in the range of the array. Otherwise, linear in `idx - size()`.
2. Logarithmic in the size of the container.
3. Logarithmic in the size of the container.
4. Logarithmic in the size of the container.

## Notes

!!! danger "Undefined behavior and runtime assertions"

    1. If the element with key `idx` does not exist, the behavior is undefined.
    2. If the element with key `key` does not exist, the behavior is undefined and is **guarded by a
       [runtime assertion](../../features/assertions.md)**!

1. The non-const version may add values: If `idx` is beyond the range of the array (i.e., `idx >= size()`), then the
   array is silently filled up with `#!json null` values to make `idx` a valid reference to the last stored element. In
   case the value was `#!json null` before, it is converted to an array.

2. If `key` is not found in the object, then it is silently added to the object and filled with a `#!json null` value to
   make `key` a valid reference. In case the value was `#!json null` before, it is converted to an object.

3. See 2.

4. `null` values are created in arrays and objects if necessary.
   
    In particular:

    - If the JSON pointer points to an object key that does not exist, it is created and filled with a `#!json null`
      value before a reference to it is returned.
    - If the JSON pointer points to an array index that does not exist, it is created and filled with a `#!json null`
      value before a reference to it is returned. All indices between the current maximum and the given index are also
      filled with `#!json null`.
    - The special value `-` is treated as a synonym for the index past the end.

## Examples

??? example "Example (1): access specified array element"

    The example below shows how array elements can be read and written using `[]` operator. Note the addition of
    `#!json null` values.
        
    ```cpp
    --8<-- "examples/operatorarray__size_type.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/operatorarray__size_type.output"
    ```

??? example "Example (1): access specified array element"

    The example below shows how array elements can be read using the `[]` operator.

    ```cpp
    --8<-- "examples/operatorarray__size_type_const.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/operatorarray__size_type_const.output"
    ```

??? example "Example (2): access specified object element"

    The example below shows how object elements can be read and written using the `[]` operator.
    
    ```cpp
    --8<-- "examples/operatorarray__key_type.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/operatorarray__key_type.output"
    ```

??? example "Example (2): access specified object element (const)"

    The example below shows how object elements can be read using the `[]` operator.
    
    ```cpp
    --8<-- "examples/operatorarray__key_type_const.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/operatorarray__key_type_const.output"
    ```

??? example "Example (4): access specified element via JSON Pointer"

    The example below shows how values can be read and written using JSON Pointers.
    
    ```cpp
    --8<-- "examples/operatorjson_pointer.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/operatorjson_pointer.output"
    ```

??? example "Example (4): access specified element via JSON Pointer (const)"

    The example below shows how values can be read using JSON Pointers.
    
    ```cpp
    --8<-- "examples/operatorjson_pointer_const.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/operatorjson_pointer_const.output"
    ```

## See also

- see [`at`](at.md) for access by reference with range checking
- see [`value`](value.md) for access with default value

## Version history

1. Added in version 1.0.0.
2. Added in version 1.0.0. Added overloads for `T* key` in version 1.1.0. Removed overloads for `T* key` (replaced by 3) in version 3.11.0.
3. Added in version 3.11.0.
4. Added in version 2.0.0.
