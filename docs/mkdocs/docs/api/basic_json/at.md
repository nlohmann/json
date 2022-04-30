# <small>nlohmann::basic_json::</small>at

```cpp
// (1)
reference at(size_type idx);
const_reference at(size_type idx) const;

// (2)
reference at(const typename object_t::key_type& key);
const_reference at(const typename object_t::key_type& key) const;

// (3)
template<typename KeyType>
reference at(KeyType&& key);
template<typename KeyType>
const_reference at(KeyType&& key) const;

// (4)
reference at(const json_pointer& ptr);
const_reference at(const json_pointer& ptr) const;
```

1. Returns a reference to the array element at specified location `idx`, with bounds checking.
2. Returns a reference to the object element with specified key `key`, with bounds checking.
3. See 2. This overload is only available if `KeyType` is comparable with `#!cpp typename object_t::key_type` and
   `#!cpp typename object_comparator_t::is_transparent` denotes a type.
4. Returns a reference to the element at specified JSON pointer `ptr`, with bounds checking.

## Template parameters

`KeyType`
:   A type for an object key other than [`json_pointer`](../json_pointer/index.md) that is comparable with
    [`string_t`](string_t.md) using  [`object_comparator_t`](object_comparator_t.md).
    This can also be a string view (C++17).

## Parameters

`idx` (in)
:   index of the element to access

`key` (in)
:   object key of the elements to access

`ptr` (in)
:   JSON pointer to the desired element

## Return value

1. reference to the element at index `idx`
2. reference to the element at key `key`
3. reference to the element at key `key`
4. reference to the element pointed to by `ptr`

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Exceptions

1. The function can throw the following exceptions:
    - Throws [`type_error.304`](../../home/exceptions.md#jsonexceptiontype_error304) if the JSON value is not an array;
      in this case, calling `at` with an index makes no sense. See example below.
    - Throws [`out_of_range.401`](../../home/exceptions.md#jsonexceptionout_of_range401) if the index `idx` is out of
      range of the array; that is, `idx >= size()`. See example below.
2. The function can throw the following exceptions:
    - Throws [`type_error.304`](../../home/exceptions.md#jsonexceptiontype_error304) if the JSON value is not an object;
      in this case, calling `at` with a key makes no sense. See example below.
    - Throws [`out_of_range.403`](../../home/exceptions.md#jsonexceptionout_of_range403) if the key `key` is not
      stored in the object; that is, `find(key) == end()`. See example below.
3. See 2.
4. The function can throw the following exceptions:
    - Throws [`parse_error.106`](../../home/exceptions.md#jsonexceptionparse_error106) if an array index in the passed
      JSON pointer `ptr` begins with '0'. See example below.
    - Throws [`parse_error.109`](../../home/exceptions.md#jsonexceptionparse_error109) if an array index in the passed
      JSON pointer `ptr` is not a number. See example below.
    - Throws [`out_of_range.401`](../../home/exceptions.md#jsonexceptionout_of_range401) if an array index in the passed
      JSON pointer `ptr` is out of range. See example below.
    - Throws [`out_of_range.402`](../../home/exceptions.md#jsonexceptionout_of_range402) if the array index '-' is used
      in the passed JSON pointer `ptr`. As `at` provides checked access (and no elements are implicitly inserted), the
      index '-' is always invalid. See example below.
    - Throws [`out_of_range.403`](../../home/exceptions.md#jsonexceptionout_of_range403) if the JSON pointer describes a
      key of an object which cannot be found. See example below.
    - Throws [`out_of_range.404`](../../home/exceptions.md#jsonexceptionout_of_range404) if the JSON pointer `ptr` can
      not be resolved. See example below.

## Complexity

1. Constant.
2. Logarithmic in the size of the container.
3. Logarithmic in the size of the container.
4. Logarithmic in the size of the container.

## Examples

??? example "Example: (1) access specified array element with bounds checking"

    The example below shows how array elements can be read and written using `at()`. It also demonstrates the different
    exceptions that can be thrown.
    
    ```cpp
    --8<-- "examples/at__size_type.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/at__size_type.output"
    ```

??? example "Example: (1) access specified array element with bounds checking"

    The example below shows how array elements can be read using `at()`. It also demonstrates the different exceptions
    that can be thrown.
        
    ```cpp
    --8<-- "examples/at__size_type_const.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/at__size_type_const.output"
    ```

??? example "Example: (2) access specified object element with bounds checking"

    The example below shows how object elements can be read and written using `at()`. It also demonstrates the different
    exceptions that can be thrown.
        
    ```cpp
    --8<-- "examples/at__object_t_key_type.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/at__object_t_key_type.output"
    ```

??? example "Example (2) access specified object element with bounds checking"

    The example below shows how object elements can be read using `at()`. It also demonstrates the different exceptions
    that can be thrown.
        
    ```cpp
    --8<-- "examples/at__object_t_key_type_const.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/at__object_t_key_type_const.output"
    ```

??? example "Example (4) access specified element via JSON Pointer"

    The example below shows how object elements can be read and written using `at()`. It also demonstrates the different
    exceptions that can be thrown.
        
    ```cpp
    --8<-- "examples/at_json_pointer.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/at_json_pointer.output"
    ```

??? example "Example (4) access specified element via JSON Pointer"

    The example below shows how object elements can be read using `at()`. It also demonstrates the different exceptions
    that can be thrown.
        
    ```cpp
    --8<-- "examples/at_json_pointer_const.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/at_json_pointer_const.output"
    ```

## See also

- see [`operator[]`](operator%5B%5D.md) for unchecked access by reference
- see [`value`](value.md) for access with default value

## Version history

1. Added in version 1.0.0.
2. Added in version 1.0.0.
3. Added in version 3.11.0.
4. Added in version 2.0.0.
