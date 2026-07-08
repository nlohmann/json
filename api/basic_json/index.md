# nlohmann::basic_json

Defined in header `<nlohmann/json.hpp>`

```
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

| Template parameter   | Description                                                               | Derived type                                                                              |
| -------------------- | ------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| `ObjectType`         | type for JSON objects                                                     | [`object_t`](https://json.nlohmann.me/api/basic_json/object_t/index.md)                   |
| `ArrayType`          | type for JSON arrays                                                      | [`array_t`](https://json.nlohmann.me/api/basic_json/array_t/index.md)                     |
| `StringType`         | type for JSON strings and object keys                                     | [`string_t`](https://json.nlohmann.me/api/basic_json/string_t/index.md)                   |
| `BooleanType`        | type for JSON booleans                                                    | [`boolean_t`](https://json.nlohmann.me/api/basic_json/boolean_t/index.md)                 |
| `NumberIntegerType`  | type for JSON integer numbers                                             | [`number_integer_t`](https://json.nlohmann.me/api/basic_json/number_integer_t/index.md)   |
| `NumberUnsignedType` | type for JSON unsigned integer numbers                                    | [`number_unsigned_t`](https://json.nlohmann.me/api/basic_json/number_unsigned_t/index.md) |
| `NumberFloatType`    | type for JSON floating-point numbers                                      | [`number_float_t`](https://json.nlohmann.me/api/basic_json/number_float_t/index.md)       |
| `AllocatorType`      | type of the allocator to use                                              |                                                                                           |
| `JSONSerializer`     | the serializer to resolve internal calls to `to_json()` and `from_json()` | [`json_serializer`](https://json.nlohmann.me/api/basic_json/json_serializer/index.md)     |
| `BinaryType`         | type for binary arrays                                                    | [`binary_t`](https://json.nlohmann.me/api/basic_json/binary_t/index.md)                   |
| `CustomBaseClass`    | extension point for user code                                             | [`json_base_class_t`](https://json.nlohmann.me/api/basic_json/json_base_class_t/index.md) |

## Specializations

- [**json**](https://json.nlohmann.me/api/json/index.md) - default specialization
- [**ordered_json**](https://json.nlohmann.me/api/ordered_json/index.md) - a specialization that maintains the insertion order of object keys

## Iterator invalidation

All operations that add values to an **array** ([`push_back`](https://json.nlohmann.me/api/basic_json/push_back/index.md) , [`operator+=`](https://json.nlohmann.me/api/basic_json/operator%2B%3D/index.md), [`emplace_back`](https://json.nlohmann.me/api/basic_json/emplace_back/index.md), [`insert`](https://json.nlohmann.me/api/basic_json/insert/index.md), and [`operator[]`](https://json.nlohmann.me/api/basic_json/operator%5B%5D/index.md) for a non-existing index) can yield a reallocation, in which case all iterators (including the [`end()`](https://json.nlohmann.me/api/basic_json/end/index.md) iterator) and all references to the elements are invalidated.

For [`ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md), also all operations that add a value to an **object** ([`push_back`](https://json.nlohmann.me/api/basic_json/push_back/index.md), [`operator+=`](https://json.nlohmann.me/api/basic_json/operator%2B%3D/index.md), [`emplace`](https://json.nlohmann.me/api/basic_json/emplace/index.md), [`insert`](https://json.nlohmann.me/api/basic_json/insert/index.md), [`update`](https://json.nlohmann.me/api/basic_json/update/index.md), and [`operator[]`](https://json.nlohmann.me/api/basic_json/operator%5B%5D/index.md) for a non-existing key) can yield a reallocation, in which case all iterators (including the [`end()`](https://json.nlohmann.me/api/basic_json/end/index.md) iterator) and all references to the elements are invalidated.

## Requirements

The class satisfies the following concept requirements:

### Basic

- [DefaultConstructible](https://en.cppreference.com/w/cpp/named_req/DefaultConstructible): JSON values can be default-constructed. The result will be a JSON null value.
- [MoveConstructible](https://en.cppreference.com/w/cpp/named_req/MoveConstructible): A JSON value can be constructed from an rvalue argument.
- [CopyConstructible](https://en.cppreference.com/w/cpp/named_req/CopyConstructible): A JSON value can be copy-constructed from an lvalue expression.
- [MoveAssignable](https://en.cppreference.com/w/cpp/named_req/MoveAssignable): A JSON value can be assigned from an rvalue argument.
- [CopyAssignable](https://en.cppreference.com/w/cpp/named_req/CopyAssignable): A JSON value can be copy-assigned from an lvalue expression.
- [Destructible](https://en.cppreference.com/w/cpp/named_req/Destructible): JSON values can be destructed.

### Layout

- [StandardLayoutType](https://en.cppreference.com/w/cpp/named_req/StandardLayoutType): JSON values have [standard layout](https://en.cppreference.com/w/cpp/language/data_members#Standard_layout): All non-static data members are private and standard layout types, the class has no virtual functions or (virtual) base classes.

### Library-wide

- [EqualityComparable](https://en.cppreference.com/w/cpp/named_req/EqualityComparable): JSON values can be compared with `==`, see [`operator==`](https://json.nlohmann.me/api/basic_json/operator_eq/index.md).
- [LessThanComparable](https://en.cppreference.com/w/cpp/named_req/LessThanComparable): JSON values can be compared with `<`, see [`operator<`](https://json.nlohmann.me/api/basic_json/operator_le/index.md).
- [Swappable](https://en.cppreference.com/w/cpp/named_req/Swappable): Any JSON lvalue or rvalue of can be swapped with any lvalue or rvalue of other compatible types, using unqualified function `swap`.
- [NullablePointer](https://en.cppreference.com/w/cpp/named_req/NullablePointer): JSON values can be compared against `std::nullptr_t` objects which are used to model the `null` value.

### Container

- [Container](https://en.cppreference.com/w/cpp/named_req/Container): JSON values can be used like STL containers and provide iterator access.
- [ReversibleContainer](https://en.cppreference.com/w/cpp/named_req/ReversibleContainer): JSON values can be used like STL containers and provide reverse iterator access.

## Member types

- [**adl_serializer**](https://json.nlohmann.me/api/adl_serializer/index.md) - the default serializer
- [**value_t**](https://json.nlohmann.me/api/basic_json/value_t/index.md) - the JSON type enumeration
- [**json_pointer**](https://json.nlohmann.me/api/json_pointer/index.md) - JSON Pointer implementation
- [**json_serializer**](https://json.nlohmann.me/api/basic_json/json_serializer/index.md) - type of the serializer to for conversions from/to JSON
- [**error_handler_t**](https://json.nlohmann.me/api/basic_json/error_handler_t/index.md) - type to choose behavior on decoding errors
- [**cbor_tag_handler_t**](https://json.nlohmann.me/api/basic_json/cbor_tag_handler_t/index.md) - type to choose how to handle CBOR tags
- **initializer_list_t** - type for initializer lists of `basic_json` values
- [**input_format_t**](https://json.nlohmann.me/api/basic_json/input_format_t/index.md) - type to choose the format to parse
- [**json_sax_t**](https://json.nlohmann.me/api/json_sax/index.md) - type for SAX events

### Exceptions

- [**exception**](https://json.nlohmann.me/api/basic_json/exception/index.md) - general exception of the `basic_json` class
  - [**parse_error**](https://json.nlohmann.me/api/basic_json/parse_error/index.md) - exception indicating a parse error
  - [**invalid_iterator**](https://json.nlohmann.me/api/basic_json/invalid_iterator/index.md) - exception indicating errors with iterators
  - [**type_error**](https://json.nlohmann.me/api/basic_json/type_error/index.md) - exception indicating executing a member function with a wrong type
  - [**out_of_range**](https://json.nlohmann.me/api/basic_json/out_of_range/index.md) - exception indicating access out of the defined range
  - [**other_error**](https://json.nlohmann.me/api/basic_json/other_error/index.md) - exception indicating other library errors

### Container types

| Type                     | Definition                                                                                                |
| ------------------------ | --------------------------------------------------------------------------------------------------------- |
| `value_type`             | `basic_json`                                                                                              |
| `reference`              | `value_type&`                                                                                             |
| `const_reference`        | `const value_type&`                                                                                       |
| `difference_type`        | `std::ptrdiff_t`                                                                                          |
| `size_type`              | `std::size_t`                                                                                             |
| `allocator_type`         | `AllocatorType<basic_json>`                                                                               |
| `pointer`                | `std::allocator_traits<allocator_type>::pointer`                                                          |
| `const_pointer`          | `std::allocator_traits<allocator_type>::const_pointer`                                                    |
| `iterator`               | [LegacyBidirectionalIterator](https://en.cppreference.com/w/cpp/named_req/BidirectionalIterator)          |
| `const_iterator`         | constant [LegacyBidirectionalIterator](https://en.cppreference.com/w/cpp/named_req/BidirectionalIterator) |
| `reverse_iterator`       | reverse iterator, derived from `iterator`                                                                 |
| `const_reverse_iterator` | reverse iterator, derived from `const_iterator`                                                           |
| `iteration_proxy`        | helper type for [`items`](https://json.nlohmann.me/api/basic_json/items/index.md) function                |

### JSON value data types

- [**array_t**](https://json.nlohmann.me/api/basic_json/array_t/index.md) - type for arrays
- [**binary_t**](https://json.nlohmann.me/api/basic_json/binary_t/index.md) - type for binary arrays
- [**boolean_t**](https://json.nlohmann.me/api/basic_json/boolean_t/index.md) - type for booleans
- [**default_object_comparator_t**](https://json.nlohmann.me/api/basic_json/default_object_comparator_t/index.md) - default comparator for objects
- [**number_float_t**](https://json.nlohmann.me/api/basic_json/number_float_t/index.md) - type for numbers (floating-point)
- [**number_integer_t**](https://json.nlohmann.me/api/basic_json/number_integer_t/index.md) - type for numbers (integer)
- [**number_unsigned_t**](https://json.nlohmann.me/api/basic_json/number_unsigned_t/index.md) - type for numbers (unsigned)
- [**object_comparator_t**](https://json.nlohmann.me/api/basic_json/object_comparator_t/index.md) - comparator for objects
- [**object_t**](https://json.nlohmann.me/api/basic_json/object_t/index.md) - type for objects
- [**string_t**](https://json.nlohmann.me/api/basic_json/string_t/index.md) - type for strings

### Parser callback

- [**parse_event_t**](https://json.nlohmann.me/api/basic_json/parse_event_t/index.md) - parser event types
- [**parser_callback_t**](https://json.nlohmann.me/api/basic_json/parser_callback_t/index.md) - per-element parser callback type

## Member functions

- [(constructor)](https://json.nlohmann.me/api/basic_json/basic_json/index.md)
- [(destructor)](https://json.nlohmann.me/api/basic_json/~basic_json/index.md)
- [**operator=**](https://json.nlohmann.me/api/basic_json/operator%3D/index.md) - copy assignment
- [**array**](https://json.nlohmann.me/api/basic_json/array/index.md) (*static*) - explicitly create an array
- [**binary**](https://json.nlohmann.me/api/basic_json/binary/index.md) (*static*) - explicitly create a binary array
- [**object**](https://json.nlohmann.me/api/basic_json/object/index.md) (*static*) - explicitly create an object

### Object inspection

Functions to inspect the type of a JSON value.

- [**type**](https://json.nlohmann.me/api/basic_json/type/index.md) - return the type of the JSON value
- [**operator value_t**](https://json.nlohmann.me/api/basic_json/operator_value_t/index.md) - return the type of the JSON value
- [**type_name**](https://json.nlohmann.me/api/basic_json/type_name/index.md) - return the type as string
- [**is_primitive**](https://json.nlohmann.me/api/basic_json/is_primitive/index.md) - return whether the type is primitive
- [**is_structured**](https://json.nlohmann.me/api/basic_json/is_structured/index.md) - return whether the type is structured
- [**is_null**](https://json.nlohmann.me/api/basic_json/is_null/index.md) - return whether the value is null
- [**is_boolean**](https://json.nlohmann.me/api/basic_json/is_boolean/index.md) - return whether the value is a boolean
- [**is_number**](https://json.nlohmann.me/api/basic_json/is_number/index.md) - return whether the value is a number
- [**is_number_integer**](https://json.nlohmann.me/api/basic_json/is_number_integer/index.md) - return whether the value is an integer number
- [**is_number_unsigned**](https://json.nlohmann.me/api/basic_json/is_number_unsigned/index.md) - return whether the value is an unsigned integer number
- [**is_number_float**](https://json.nlohmann.me/api/basic_json/is_number_float/index.md) - return whether the value is a floating-point number
- [**is_object**](https://json.nlohmann.me/api/basic_json/is_object/index.md) - return whether the value is an object
- [**is_array**](https://json.nlohmann.me/api/basic_json/is_array/index.md) - return whether the value is an array
- [**is_string**](https://json.nlohmann.me/api/basic_json/is_string/index.md) - return whether the value is a string
- [**is_binary**](https://json.nlohmann.me/api/basic_json/is_binary/index.md) - return whether the value is a binary array
- [**is_discarded**](https://json.nlohmann.me/api/basic_json/is_discarded/index.md) - return whether the value is discarded

Optional functions to access the [diagnostic positions](https://json.nlohmann.me/api/macros/json_diagnostic_positions/index.md).

- [**start_pos**](https://json.nlohmann.me/api/basic_json/start_pos/index.md) - return the start position of the value
- [**end_pos**](https://json.nlohmann.me/api/basic_json/end_pos/index.md) - return the one past the end position of the value

### Value access

Direct access to the stored value of a JSON value.

- [**get**](https://json.nlohmann.me/api/basic_json/get/index.md) - get a value
- [**get_to**](https://json.nlohmann.me/api/basic_json/get_to/index.md) - get a value and write it to a destination
- [**get_ptr**](https://json.nlohmann.me/api/basic_json/get_ptr/index.md) - get a pointer value
- [**get_ref**](https://json.nlohmann.me/api/basic_json/get_ref/index.md) - get a reference value
- [**operator ValueType**](https://json.nlohmann.me/api/basic_json/operator_ValueType/index.md) - get a value
- [**get_binary**](https://json.nlohmann.me/api/basic_json/get_binary/index.md) - get a binary value

### Element access

Access to the JSON value

- [**at**](https://json.nlohmann.me/api/basic_json/at/index.md) - access specified element with bounds checking
- [**operator[]**](https://json.nlohmann.me/api/basic_json/operator%5B%5D/index.md) - access specified element
- [**value**](https://json.nlohmann.me/api/basic_json/value/index.md) - access specified object element with default value
- [**front**](https://json.nlohmann.me/api/basic_json/front/index.md) - access the first element
- [**back**](https://json.nlohmann.me/api/basic_json/back/index.md) - access the last element

### Lookup

- [**find**](https://json.nlohmann.me/api/basic_json/find/index.md) - find an element in a JSON object
- [**count**](https://json.nlohmann.me/api/basic_json/count/index.md) - returns the number of occurrences of a key in a JSON object
- [**contains**](https://json.nlohmann.me/api/basic_json/contains/index.md) - check the existence of an element in a JSON object

### Iterators

- [**begin**](https://json.nlohmann.me/api/basic_json/begin/index.md) - returns an iterator to the first element
- [**cbegin**](https://json.nlohmann.me/api/basic_json/cbegin/index.md) - returns a const iterator to the first element
- [**end**](https://json.nlohmann.me/api/basic_json/end/index.md) - returns an iterator to one past the last element
- [**cend**](https://json.nlohmann.me/api/basic_json/cend/index.md) - returns a const iterator to one past the last element
- [**rbegin**](https://json.nlohmann.me/api/basic_json/rbegin/index.md) - returns an iterator to the reverse-beginning
- [**rend**](https://json.nlohmann.me/api/basic_json/rend/index.md) - returns an iterator to the reverse-end
- [**crbegin**](https://json.nlohmann.me/api/basic_json/crbegin/index.md) - returns a const iterator to the reverse-beginning
- [**crend**](https://json.nlohmann.me/api/basic_json/crend/index.md) - returns a const iterator to the reverse-end
- [**items**](https://json.nlohmann.me/api/basic_json/items/index.md) - wrapper to access iterator member functions in range-based for

### Capacity

- [**empty**](https://json.nlohmann.me/api/basic_json/empty/index.md) - checks whether the container is empty
- [**size**](https://json.nlohmann.me/api/basic_json/size/index.md) - returns the number of elements
- [**max_size**](https://json.nlohmann.me/api/basic_json/max_size/index.md) - returns the maximum possible number of elements

### Modifiers

- [**clear**](https://json.nlohmann.me/api/basic_json/clear/index.md) - clears the contents
- [**push_back**](https://json.nlohmann.me/api/basic_json/push_back/index.md) - add a value to an array/object
- [**operator+=**](https://json.nlohmann.me/api/basic_json/operator%2B%3D/index.md) - add a value to an array/object
- [**emplace_back**](https://json.nlohmann.me/api/basic_json/emplace_back/index.md) - add a value to an array
- [**emplace**](https://json.nlohmann.me/api/basic_json/emplace/index.md) - add a value to an object if a key does not exist
- [**erase**](https://json.nlohmann.me/api/basic_json/erase/index.md) - remove elements
- [**insert**](https://json.nlohmann.me/api/basic_json/insert/index.md) - inserts elements
- [**update**](https://json.nlohmann.me/api/basic_json/update/index.md) - updates a JSON object from another object, overwriting existing keys
- [**swap**](https://json.nlohmann.me/api/basic_json/swap/index.md) - exchanges the values

### Lexicographical comparison operators

- [**operator==**](https://json.nlohmann.me/api/basic_json/operator_eq/index.md) - comparison: equal
- [**operator!=**](https://json.nlohmann.me/api/basic_json/operator_ne/index.md) - comparison: not equal
- [**operator\<**](https://json.nlohmann.me/api/basic_json/operator_lt/index.md) - comparison: less than
- [**operator>**](https://json.nlohmann.me/api/basic_json/operator_gt/index.md) - comparison: greater than
- [**operator\<=**](https://json.nlohmann.me/api/basic_json/operator_le/index.md) - comparison: less than or equal
- [**operator>=**](https://json.nlohmann.me/api/basic_json/operator_ge/index.md) - comparison: greater than or equal
- [**operator\<=>**](https://json.nlohmann.me/api/basic_json/operator_spaceship/index.md) - comparison: 3-way

### Serialization / Dumping

- [**dump**](https://json.nlohmann.me/api/basic_json/dump/index.md) - serialization

### Deserialization / Parsing

- [**parse**](https://json.nlohmann.me/api/basic_json/parse/index.md) (*static*) - deserialize from a compatible input
- [**accept**](https://json.nlohmann.me/api/basic_json/accept/index.md) (*static*) - check if the input is valid JSON
- [**sax_parse**](https://json.nlohmann.me/api/basic_json/sax_parse/index.md) (*static*) - generate SAX events

### JSON Pointer functions

- [**flatten**](https://json.nlohmann.me/api/basic_json/flatten/index.md) - return flattened JSON value
- [**unflatten**](https://json.nlohmann.me/api/basic_json/unflatten/index.md) - unflatten a previously flattened JSON value

### JSON Patch functions

- [**patch**](https://json.nlohmann.me/api/basic_json/patch/index.md) - applies a JSON patch
- [**patch_inplace**](https://json.nlohmann.me/api/basic_json/patch_inplace/index.md) - applies a JSON patch in place
- [**diff**](https://json.nlohmann.me/api/basic_json/diff/index.md) (*static*) - creates a diff as a JSON patch

### JSON Merge Patch functions

- [**merge_patch**](https://json.nlohmann.me/api/basic_json/merge_patch/index.md) - applies a JSON Merge Patch

## Static functions

- [**meta**](https://json.nlohmann.me/api/basic_json/meta/index.md) - returns version information on the library
- [**get_allocator**](https://json.nlohmann.me/api/basic_json/get_allocator/index.md) - returns the allocator associated with the container

### Binary formats

- [**from_bjdata**](https://json.nlohmann.me/api/basic_json/from_bjdata/index.md) (*static*) - create a JSON value from an input in BJData format
- [**from_bson**](https://json.nlohmann.me/api/basic_json/from_bson/index.md) (*static*) - create a JSON value from an input in BSON format
- [**from_cbor**](https://json.nlohmann.me/api/basic_json/from_cbor/index.md) (*static*) - create a JSON value from an input in CBOR format
- [**from_msgpack**](https://json.nlohmann.me/api/basic_json/from_msgpack/index.md) (*static*) - create a JSON value from an input in MessagePack format
- [**from_ubjson**](https://json.nlohmann.me/api/basic_json/from_ubjson/index.md) (*static*) - create a JSON value from an input in UBJSON format
- [**to_bjdata**](https://json.nlohmann.me/api/basic_json/to_bjdata/index.md) (*static*) - create a BJData serialization of a given JSON value
- [**to_bson**](https://json.nlohmann.me/api/basic_json/to_bson/index.md) (*static*) - create a BSON serialization of a given JSON value
- [**to_cbor**](https://json.nlohmann.me/api/basic_json/to_cbor/index.md) (*static*) - create a CBOR serialization of a given JSON value
- [**to_msgpack**](https://json.nlohmann.me/api/basic_json/to_msgpack/index.md) (*static*) - create a MessagePack serialization of a given JSON value
- [**to_ubjson**](https://json.nlohmann.me/api/basic_json/to_ubjson/index.md) (*static*) - create a UBJSON serialization of a given JSON value

## Non-member functions

- [**operator\<<(std::ostream&)**](https://json.nlohmann.me/api/operator_ltlt/index.md) - serialize to stream
- [**operator>>(std::istream&)**](https://json.nlohmann.me/api/operator_gtgt/index.md) - deserialize from stream
- [**to_string**](https://json.nlohmann.me/api/basic_json/to_string/index.md) - user-defined `to_string` function for JSON values
- [**format_as**](https://json.nlohmann.me/api/basic_json/format_as/index.md) - user-defined `format_as` function for JSON values (fmt support)

## Literals

- [**operator""\_json**](https://json.nlohmann.me/api/operator_literal_json/index.md) - user-defined string literal for JSON values

## Helper classes

- [**std::formatter\<basic_json>**](https://json.nlohmann.me/api/basic_json/std_formatter/index.md) - make JSON values formattable with `std::format`
- [**std::hash\<basic_json>**](https://json.nlohmann.me/api/basic_json/std_hash/index.md) - return a hash value for a JSON object
- [**std::swap\<basic_json>**](https://json.nlohmann.me/api/basic_json/std_swap/index.md) - exchanges the values of two JSON objects

## Examples

Example

The example shows how the library is used.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON object
    json j =
    {
        {"pi", 3.141},
        {"happy", true},
        {"name", "Niels"},
        {"nothing", nullptr},
        {
            "answer", {
                {"everything", 42}
            }
        },
        {"list", {1, 0, 2}},
        {
            "object", {
                {"currency", "USD"},
                {"value", 42.99}
            }
        }
    };

    // add new values
    j["new"]["key"]["value"] = {"another", "list"};

    // count elements
    auto s = j.size();
    j["size"] = s;

    // pretty print with indent of 4 spaces
    std::cout << std::setw(4) << j << '\n';
}
```

Output:

```
{
    "answer": {
        "everything": 42
    },
    "happy": true,
    "list": [
        1,
        0,
        2
    ],
    "name": "Niels",
    "new": {
        "key": {
            "value": [
                "another",
                "list"
            ]
        }
    },
    "nothing": null,
    "object": {
        "currency": "USD",
        "value": 42.99
    },
    "pi": 3.141,
    "size": 8
}
```

## See also

- [RFC 8259: The JavaScript Object Notation (JSON) Data Interchange Format](https://tools.ietf.org/html/rfc8259)

## Version history

- Added in version 1.0.0.
