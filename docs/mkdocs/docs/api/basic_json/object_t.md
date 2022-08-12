# <small>nlohmann::basic_json::</small>object_t

```cpp
using object_t = ObjectType<StringType,
                            basic_json,
                            default_object_comparator_t,
                            AllocatorType<std::pair<const StringType, basic_json>>>;
```

The type used to store JSON objects.

[RFC 8259](https://tools.ietf.org/html/rfc8259) describes JSON objects as follows:
> An object is an unordered collection of zero or more name/value pairs, where a name is a string and a value is a
> string, number, boolean, null, object, or array.

To store objects in C++, a type is defined by the template parameters described below.

## Template parameters

`ObjectType`
:   the container to store objects (e.g., `std::map` or `std::unordered_map`)

`StringType`
:   the type of the keys or names (e.g., `std::string`). The comparison function `std::less<StringType>` is used to
    order elements inside the container.

`AllocatorType`
:   the allocator to use for objects (e.g., `std::allocator`)

## Notes

#### Default type

With the default values for `ObjectType` (`std::map`), `StringType` (`std::string`), and `AllocatorType`
(`std::allocator`), the default value for `object_t` is:

```cpp
// until C++14
std::map<
  std::string, // key_type
  basic_json, // value_type
  std::less<std::string>, // key_compare
  std::allocator<std::pair<const std::string, basic_json>> // allocator_type
>

// since C++14
std::map<
  std::string, // key_type
  basic_json, // value_type
  std::less<>, // key_compare
  std::allocator<std::pair<const std::string, basic_json>> // allocator_type
>
```

See [`default_object_comparator_t`](default_object_comparator_t.md) for more information.

#### Behavior

The choice of `object_t` influences the behavior of the JSON class. With the default type, objects have the following
behavior:

- When all names are unique, objects will be interoperable in the sense that all software implementations receiving that
  object will agree on the name-value mappings.
- When the names within an object are not unique, it is unspecified which one of the values for a given key will be
  chosen. For instance, `#!json {"key": 2, "key": 1}` could be equal to either `#!json {"key": 1}` or
  `#!json {"key": 2}`.
- Internally, name/value pairs are stored in lexicographical order of the names. Objects will also be serialized (see
  [`dump`](dump.md)) in this order. For instance, `#!json {"b": 1, "a": 2}` and `#!json {"a": 2, "b": 1}` will be stored
  and serialized as `#!json {"a": 2, "b": 1}`.
- When comparing objects, the order of the name/value pairs is irrelevant. This makes objects interoperable in the sense
  that they will not be affected by these differences. For instance, `#!json {"b": 1, "a": 2}` and
  `#!json {"a": 2, "b": 1}` will be treated as equal.

#### Limits

[RFC 8259](https://tools.ietf.org/html/rfc8259) specifies:
> An implementation may set limits on the maximum depth of nesting.

In this class, the object's limit of nesting is not explicitly constrained. However, a maximum depth of nesting may be
introduced by the compiler or runtime environment. A theoretical limit can be queried by calling the
[`max_size`](max_size.md) function of a JSON object.

#### Storage

Objects are stored as pointers in a `basic_json` type. That is, for any access to object values, a pointer of type
`object_t*` must be dereferenced.

#### Object key order

The order name/value pairs are added to the object is *not* preserved by the library. Therefore, iterating an object may
return name/value pairs in a different order than they were originally stored. In fact, keys will be traversed in
alphabetical order as `std::map` with `std::less` is used by default. Please note this behavior conforms to
[RFC 8259](https://tools.ietf.org/html/rfc8259), because any order implements the specified "unordered" nature of JSON
objects.

## Examples

??? example

    The following code shows that `object_t` is by default, a typedef to `#!cpp std::map<json::string_t, json>`.
     
    ```cpp
    --8<-- "examples/object_t.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/object_t.output"
    ```

## Version history

- Added in version 1.0.0.
