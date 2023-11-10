# <small>nlohmann::</small>basic_json

<small>Defined in header `<nlohmann/json.hpp>`</small>

```cpp
template<
    template<typename U, typename V, typename... Args> class ObjectType = std::map,
    template<typename U, typename... Args> class ArrayType = std::vector,
    class StringType = std::string,
    class BooleanType = bool,
    class NumberIntegerType = std::int64_t,
    class NumberUnsignedType = std::uint64_t,
    class NumberFloatType = double,
    template<typename U> class AllocatorType = std::allocator,
    template<typename T, typename SFINAE = void> class JSONSerializer = adl_serializer,
    class BinaryType = std::vector<std::uint8_t>,
    class CustomBaseClass = void
>
class basic_json;
```

## Template parameters

| Template parameter   | Description                                                               | Derived type                                |
|----------------------|---------------------------------------------------------------------------|---------------------------------------------|
| `ObjectType`         | type for JSON objects                                                     | [`object_t`](object_t.md)                   |
| `ArrayType`          | type for JSON arrays                                                      | [`array_t`](array_t.md)                     |
| `StringType`         | type for JSON strings and object keys                                     | [`string_t`](string_t.md)                   |
| `BooleanType`        | type for JSON booleans                                                    | [`boolean_t`](boolean_t.md)                 |
| `NumberIntegerType`  | type for JSON integer numbers                                             | [`number_integer_t`](number_integer_t.md)   |
| `NumberUnsignedType` | type for JSON unsigned integer numbers                                    | [`number_unsigned_t`](number_unsigned_t.md) |
| `NumberFloatType`    | type for JSON floating-point numbers                                      | [`number_float_t`](number_float_t.md)       |
| `AllocatorType`      | type of the allocator to use                                              |                                             |
| `JSONSerializer`     | the serializer to resolve internal calls to `to_json()` and `from_json()` | [`json_serializer`](json_serializer.md)     |
| `BinaryType`         | type for binary arrays                                                    | [`binary_t`](binary_t.md)                   |
| `CustomBaseClass`    | extension point for user code                                             | [`json_base_class_t`](json_base_class_t.md) |

## Specializations

- [**json**](../json.md) - default specialization
- [**ordered_json**](../ordered_json.md) - specialization that maintains the insertion order of object keys

## Iterator invalidation

Todo

## Requirements

The class satisfies the following concept requirements:

### Basic

- [DefaultConstructible](https://en.cppreference.com/w/cpp/named_req/DefaultConstructible): JSON values can be default
  constructed. The result will be a JSON null value.
- [MoveConstructible](https://en.cppreference.com/w/cpp/named_req/MoveConstructible): A JSON value can be constructed
  from an rvalue argument.
- [CopyConstructible](https://en.cppreference.com/w/cpp/named_req/CopyConstructible): A JSON value can be
  copy-constructed from an lvalue expression.
- [MoveAssignable](https://en.cppreference.com/w/cpp/named_req/MoveAssignable): A JSON value can be assigned from an
  rvalue argument.
- [CopyAssignable](https://en.cppreference.com/w/cpp/named_req/CopyAssignable): A JSON value can be copy-assigned from
  an lvalue expression.
- [Destructible](https://en.cppreference.com/w/cpp/named_req/Destructible): JSON values can be destructed.

### Layout

- [StandardLayoutType](https://en.cppreference.com/w/cpp/named_req/StandardLayoutType): JSON values have
  [standard layout](https://en.cppreference.com/w/cpp/language/data_members#Standard_layout): All non-static data
  members are private and standard layout types, the class has no virtual functions or (virtual) base classes.

### Library-wide

- [EqualityComparable](https://en.cppreference.com/w/cpp/named_req/EqualityComparable): JSON values can be compared with
  `==`, see [`operator==`](operator_eq.md).
- [LessThanComparable](https://en.cppreference.com/w/cpp/named_req/LessThanComparable): JSON values can be compared with
  `<`, see [`operator<`](operator_le.md).
- [Swappable](https://en.cppreference.com/w/cpp/named_req/Swappable): Any JSON lvalue or rvalue of can be swapped with
  any lvalue or rvalue of other compatible types, using unqualified function `swap`.
- [NullablePointer](https://en.cppreference.com/w/cpp/named_req/NullablePointer): JSON values can be compared against
  `std::nullptr_t` objects which are used to model the `null` value.

### Container

- [Container](https://en.cppreference.com/w/cpp/named_req/Container): JSON values can be used like STL containers and
  provide iterator access.
- [ReversibleContainer](https://en.cppreference.com/w/cpp/named_req/ReversibleContainer): JSON values can be used like
  STL containers and provide reverse iterator access.

## Member types

- [**adl_serializer**](../adl_serializer/index.md) - the default serializer
- [**value_t**](value_t.md) - the JSON type enumeration
- [**json_pointer**](../json_pointer/index.md) - JSON Pointer implementation
- [**json_serializer**](json_serializer.md) - type of the serializer to for conversions from/to JSON
- [**error_handler_t**](error_handler_t.md) - type to choose behavior on decoding errors
- [**cbor_tag_handler_t**](cbor_tag_handler_t.md) - type to choose how to handle CBOR tags
- **initializer_list_t** - type for initializer lists of `basic_json` values
- [**input_format_t**](input_format_t.md) - type to choose the format to parse
- [**json_sax_t**](../json_sax/index.md) - type for SAX events

### Exceptions

- [**exception**](exception.md) - general exception of the `basic_json` class
    - [**parse_error**](parse_error.md) - exception indicating a parse error
    - [**invalid_iterator**](invalid_iterator.md) - exception indicating errors with iterators
    - [**type_error**](type_error.md) - exception indicating executing a member function with a wrong type
    - [**out_of_range**](out_of_range.md) - exception indicating access out of the defined range
    - [**other_error**](other_error.md) - exception indicating other library errors

### Container types

| Type                     | Definition                                                                                                |
|--------------------------|-----------------------------------------------------------------------------------------------------------|
| `value_type`             | `#!cpp basic_json`                                                                                        |
| `reference`              | `#!cpp value_type&`                                                                                       |
| `const_reference`        | `#!cpp const value_type&`                                                                                 |
| `difference_type`        | `#!cpp std::ptrdiff_t`                                                                                    |
| `size_type`              | `#!cpp std::size_t`                                                                                       |
| `allocator_type`         | `#!cpp AllocatorType<basic_json>`                                                                         |
| `pointer`                | `#!cpp std::allocator_traits<allocator_type>::pointer`                                                    |
| `const_pointer`          | `#!cpp std::allocator_traits<allocator_type>::const_pointer`                                              |
| `iterator`               | [LegacyBidirectionalIterator](https://en.cppreference.com/w/cpp/named_req/BidirectionalIterator)          |
| `const_iterator`         | constant [LegacyBidirectionalIterator](https://en.cppreference.com/w/cpp/named_req/BidirectionalIterator) |
| `reverse_iterator`       | reverse iterator, derived from `iterator`                                                                 |
| `const_reverse_iterator` | reverse iterator, derived from `const_iterator`                                                           |
| `iteration_proxy`        | helper type for [`items`](items.md) function                                                              |

### JSON value data types

- [**array_t**](array_t.md) - type for arrays
- [**binary_t**](binary_t.md) - type for binary arrays
- [**boolean_t**](boolean_t.md) - type for booleans
- [**default_object_comparator_t**](default_object_comparator_t.md) - default comparator for objects
- [**number_float_t**](number_float_t.md) - type for numbers (floating-point)
- [**number_integer_t**](number_integer_t.md) - type for numbers (integer)
- [**number_unsigned_t**](number_unsigned_t.md) - type for numbers (unsigned)
- [**object_comparator_t**](object_comparator_t.md) - comparator for objects
- [**object_t**](object_t.md) - type for objects
- [**string_t**](string_t.md) - type for strings

### Parser callback

- [**parse_event_t**](parse_event_t.md) - parser event types
- [**parser_callback_t**](parser_callback_t.md) - per-element parser callback type

## Member functions

- [(constructor)](basic_json.md)
- [(destructor)](~basic_json.md)
- [**operator=**](operator=.md) - copy assignment
- [**array**](array_t.md) (_static_) - explicitly create an array
- [**binary**](binary.md) (_static_) - explicitly create a binary array
- [**object**](object_t.md) (_static_) - explicitly create an object

### Object inspection

Functions to inspect the type of a JSON value.

- [**type**](type.md) - return the type of the JSON value
- [**operator value_t**](operator_value_t.md) - return the type of the JSON value
- [**type_name**](type_name.md) - return the type as string
- [**is_primitive**](is_primitive.md) - return whether type is primitive
- [**is_structured**](is_structured.md) - return whether type is structured
- [**is_null**](is_null.md) - return whether value is null
- [**is_boolean**](is_boolean.md) - return whether value is a boolean
- [**is_number**](is_number.md) - return whether value is a number
- [**is_number_integer**](is_number_integer.md) - return whether value is an integer number
- [**is_number_unsigned**](is_number_unsigned.md) - return whether value is an unsigned integer number
- [**is_number_float**](is_number_float.md) - return whether value is a floating-point number
- [**is_object**](is_object.md) - return whether value is an object
- [**is_array**](is_array.md) - return whether value is an array
- [**is_string**](is_string.md) - return whether value is a string
- [**is_binary**](is_binary.md) - return whether value is a binary array
- [**is_discarded**](is_discarded.md) - return whether value is discarded

### Value access

Direct access to the stored value of a JSON value.

- [**get**](get.md) - get a value
- [**get_to**](get_to.md) - get a value and write it to a destination
- [**get_ptr**](get_ptr.md) - get a pointer value
- [**get_ref**](get_ref.md) - get a reference value
- [**operator ValueType**](operator_ValueType.md) - get a value
- [**get_binary**](get_binary.md) - get a binary value

### Element access

Access to the JSON value

- [**at**](at.md) - access specified element with bounds checking
- [**operator[]**](operator[].md) - access specified element
- [**value**](value.md) - access specified object element with default value
- [**front**](front.md) - access the first element
- [**back**](back.md) - access the last element

### Lookup

- [**find**](find.md) - find an element in a JSON object
- [**count**](count.md) - returns the number of occurrences of a key in a JSON object
- [**contains**](contains.md) - check the existence of an element in a JSON object

### Iterators

- [**begin**](begin.md) - returns an iterator to the first element
- [**cbegin**](cbegin.md) - returns a const iterator to the first element
- [**end**](end.md) - returns an iterator to one past the last element
- [**cend**](cend.md) - returns a const iterator to one past the last element
- [**rbegin**](rbegin.md) - returns an iterator to the reverse-beginning
- [**rend**](rend.md) - returns an iterator to the reverse-end
- [**crbegin**](crbegin.md) - returns a const iterator to the reverse-beginning
- [**crend**](crend.md) - returns a const iterator to the reverse-end
- [**items**](items.md) - wrapper to access iterator member functions in range-based for

### Capacity

- [**empty**](empty.md) - checks whether the container is empty
- [**size**](size.md) - returns the number of elements
- [**max_size**](max_size.md) - returns the maximum possible number of elements

### Modifiers

- [**clear**](clear.md) - clears the contents
- [**push_back**](push_back.md) - add a value to an array/object
- [**operator+=**](operator+=.md) - add a value to an array/object
- [**emplace_back**](emplace_back.md) - add a value to an array
- [**emplace**](emplace.md) - add a value to an object if key does not exist
- [**erase**](erase.md) - remove elements
- [**insert**](insert.md) - inserts elements
- [**update**](update.md) - updates a JSON object from another object, overwriting existing keys 
- [**swap**](swap.md) - exchanges the values

### Lexicographical comparison operators

- [**operator==**](operator_eq.md) - comparison: equal
- [**operator!=**](operator_ne.md) - comparison: not equal
- [**operator<**](operator_lt.md) - comparison: less than
- [**operator>**](operator_gt.md) - comparison: greater than
- [**operator<=**](operator_le.md) - comparison: less than or equal
- [**operator>=**](operator_ge.md) - comparison: greater than or equal
- [**operator<=>**](operator_spaceship.md) - comparison: 3-way

### Serialization / Dumping

- [**dump**](dump.md) - serialization

### Deserialization / Parsing

- [**parse**](parse.md) (_static_) - deserialize from a compatible input
- [**accept**](accept.md) (_static_) - check if the input is valid JSON
- [**sax_parse**](sax_parse.md) (_static_) - generate SAX events

### JSON Pointer functions

- [**flatten**](flatten.md) - return flattened JSON value
- [**unflatten**](unflatten.md) - unflatten a previously flattened JSON value

### JSON Patch functions

- [**patch**](patch.md) - applies a JSON patch
- [**patch_inplace**](patch_inplace.md) - applies a JSON patch in place
- [**diff**](diff.md) (_static_) - creates a diff as a JSON patch

### JSON Merge Patch functions

- [**merge_patch**](merge_patch.md) - applies a JSON Merge Patch

## Static functions

- [**meta**](meta.md) - returns version information on the library
- [**get_allocator**](get_allocator.md) - returns the allocator associated with the container

### Binary formats

- [**from_bjdata**](from_bjdata.md) (_static_) - create a JSON value from an input in BJData format
- [**from_bson**](from_bson.md) (_static_) - create a JSON value from an input in BSON format
- [**from_cbor**](from_cbor.md) (_static_) - create a JSON value from an input in CBOR format
- [**from_msgpack**](from_msgpack.md) (_static_) - create a JSON value from an input in MessagePack format
- [**from_ubjson**](from_ubjson.md) (_static_) - create a JSON value from an input in UBJSON format
- [**to_bjdata**](to_bjdata.md) (_static_) - create a BJData serialization of a given JSON value
- [**to_bson**](to_bson.md) (_static_) - create a BSON serialization of a given JSON value
- [**to_cbor**](to_cbor.md) (_static_) - create a CBOR serialization of a given JSON value
- [**to_msgpack**](to_msgpack.md) (_static_) - create a MessagePack serialization of a given JSON value
- [**to_ubjson**](to_ubjson.md) (_static_) - create a UBJSON serialization of a given JSON value

## Non-member functions

- [**operator<<(std::ostream&)**](../operator_ltlt.md) - serialize to stream
- [**operator>>(std::istream&)**](../operator_gtgt.md) - deserialize from stream
- [**to_string**](to_string.md) - user-defined `to_string` function for JSON values

## Literals

- [**operator""_json**](../operator_literal_json.md) - user-defined string literal for JSON values

## Helper classes

- [**std::hash&lt;basic_json&gt;**](std_hash.md) - return a hash value for a JSON object
- [**std::swap&lt;basic_json&gt;**](std_swap.md) - exchanges the values of two JSON objects

## Examples

??? example

    The example shows how the library is used.
    
    ```cpp
    --8<-- "examples/README.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/README.output"
    ```

## See also

- [RFC 8259: The JavaScript Object Notation (JSON) Data Interchange Format](https://tools.ietf.org/html/rfc8259)

## Version history

- Added in version 1.0.0.
