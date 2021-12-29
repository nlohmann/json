# <small>nlohmann::basic_json::</small>array_t

```cpp
using array_t = ArrayType<basic_json, AllocatorType<basic_json>>;
```

The type used to store JSON arrays.

[RFC 8259](https://tools.ietf.org/html/rfc8259) describes JSON arrays as follows:
> An array is an ordered sequence of zero or more values.

To store objects in C++, a type is defined by the template parameters explained below.

## Template parameters

`ArrayType`
:   container type to store arrays (e.g., `std::vector` or `std::list`)

`AllocatorType`
:   the allocator to use for objects (e.g., `std::allocator`)

## Notes

#### Default type

With the default values for `ArrayType` (`std::vector`) and `AllocatorType` (`std::allocator`), the default value for
`array_t` is:

```cpp
std::vector<
  basic_json, // value_type
  std::allocator<basic_json> // allocator_type
>
```

#### Limits

[RFC 8259](https://tools.ietf.org/html/rfc8259) specifies:
> An implementation may set limits on the maximum depth of nesting.

In this class, the array's limit of nesting is not explicitly constrained. However, a maximum depth of nesting may be
introduced by the compiler or runtime environment. A theoretical limit can be queried by calling the
[`max_size`](max_size.md) function of a JSON array.

#### Storage

Arrays are stored as pointers in a `basic_json` type. That is, for any access to array values, a pointer of type
`#!cpp array_t*` must be dereferenced.

## Examples

??? example

    The following code shows that `array_t` is by default, a typedef to `#!cpp std::vector<nlohmann::json>`.
     
    ```cpp
    --8<-- "examples/array_t.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/array_t.output"
    ```

## Version history

- Added in version 1.0.0.
