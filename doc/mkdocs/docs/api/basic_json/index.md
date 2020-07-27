# basic_json

!!! note
    
    This page is under construction.

Defined in header `<json.hpp>`

```cpp
template<template<typename, typename, typename...> class ObjectType,  
         template<typename, typename...> class ArrayType,             
         class StringType, class BooleanType, class NumberIntegerType,
         class NumberUnsignedType, class NumberFloatType,             
         template<typename> class AllocatorType,                      
         template<typename, typename = void> class JSONSerializer,    
         class BinaryType>
class basic_json
```

## Specializations

- json
- ordered_json

## Template parameters

- ObjectType
- ArrayType
- StringType
- BooleanType
- NumberIntegerType
- NumberUnsignedType
- NumberFloatType
- AllocatorType
- JSONSerializer
- BinaryType

## Iterator invalidation

## Member types

- value_t
- json_pointer
- json_serializer
- error_handler_t
- cbor_tag_handler_t
- initializer_list_t
- input_format_t
- json_sax_t

### Exceptions

- exception
- parse_error
- invalid_iterator
- type_error
- out_of_range
- other_error

### Container types

- value_type
- reference
- const_reference
- difference_type
- size_type
- allocator_type
- pointer
- const_pointer
- iterator
- const_iterator
- reverse_iterator
- const_reverse_iterator

### JSON value data types

- object_comparator_t
- object_t
- array_t
- string_t
- boolean_t
- number_integer_t
- number_unsigned_t
- number_float_t
- binary_t

### Parser callback

- parse_event_t
- parser_callback_t

## Member functions

- (constructor)
- (destructor)
- binary (static) - explicitly create a binary array
- array (static) - explicitly create an array
- object (static) - explicitly create an object
- operator= - copy assignment

### Object inspection

Functions to inspect the type of a JSON value.

- type - return the type of the JSON value
- is_primitive - return whether type is primitive
- is_structured - return whether type is structured
- is_null - return whether value is null
- is_boolean - return whether value is a boolean
- is_number - return whether value is a number
- is_number_integer - return whether value is an integer number
- is_number_unsigned - return whether value is an unsigned integer number
- is_number_float - return whether value is a floating-point number
- is_object - return whether value is an object
- is_array - return whether value is an array
- is_string - return whether value is a string
- is_binary - return whether value is a binary array
- is_discarded - return whether value is discarded
- operator value_t - return the type of the JSON value

### Value access

Direct access to the stored value of a JSON value.

- get - get a value
- get_to - get a value
- get_ptr - get a pointer value
- get_ref - get a reference value
- operator ValueType - get a value
- get_binary - get a binary value

### Element access

Access to the JSON value

- at - access specified array element with bounds checking
- at - access specified object element with bounds checking
- operator[] - access specified array element
- operator[] - access specified object element
- value - access specified object element with default value
- front - access the first element
- back - access the last element
- erase - remove elements

### Lookup

- find - find an element in a JSON object
- count - returns the number of occurrences of a key in a JSON object
- contains - check the existence of an element in a JSON object

### Iterators

- begin - returns an iterator to the first element
- cbegin - returns a const iterator to the first element
- end - returns an iterator to one past the last element
- cend - returns a const iterator to one past the last element
- rbegin - returns an iterator to the reverse-beginning
- rend - returns an iterator to the reverse-end
- crbegin - returns a const iterator to the reverse-beginning
- crend - returns a const iterator to the reverse-end
- items - wrapper to access iterator member functions in range-based for

### Capacity

- empty - checks whether the container is empty
- size - returns the number of elements
- max_size - returns the maximum possible number of elements

### Modifiers

- clear - clears the contents
- push_back - add an object to an array
- operator+= - add an object to an array
- push_back - add an object to an object
- operator+= - add an object to an object
- emplace_back - add an object to an array
- emplace - add an object to an object if key does not exist
- insert - inserts element
- update - updates a JSON object from another object, overwriting existing keys 
- swap - exchanges the values

### Lexicographical comparison operators

- operator== - comparison: equal
- operator!= - comparison: not equal
- operator< - comparison: less than
- operator<= - comparison: less than or equal
- operator> - comparison: greater than
- operator>= - comparison: greater than or equal

### Serialization

- [**dump**](dump.md) - serialization
- to_string - user-defined to_string function for JSON values

### Deserialization

- [**parse**](parse.md) - deserialize from a compatible input
- accept - check if the input is valid JSON
- sax_parse - generate SAX events

### Convenience functions

- type_name - return the type as string

### JSON Pointer functions

- at - access specified object element with bounds checking via JSON Pointer
- operator[] - access specified element via JSON Pointer
- value - access specified object element with default value via JSON Pointer
- flatten - return flattened JSON value
- unflatten - unflatten a previously flattened JSON value

### JSON Patch functions

- patch - applies a JSON patch
- diff (static) - creates a diff as a JSON patch

### JSON Merge Patch functions

- merge_patch - applies a JSON Merge Patch

## Static functions

- [**meta**](meta.md) - returns version information on the library
- get_allocator - returns the allocator associated with the container

### Binary formats

- to_cbor - create a CBOR serialization of a given JSON value
- to_msgpack - create a MessagePack serialization of a given JSON value
- to_ubjson - create a UBJSON serialization of a given JSON value
- to_bson - create a BSON serialization of a given JSON value
- from_cbor - create a JSON value from an input in CBOR format
- from_msgpack - create a JSON value from an input in MessagePack format
- from_ubjson - create a JSON value from an input in UBJSON format
- from_bson - create a JSON value from an input in BSON format

## Non-member functions

- operator<<(std::ostream&) - serialize to stream
- operator>>(std::istream&) - deserialize from stream

## Literals

- operator""_json
- operator""_json_pointer

## Helper classes

- std::hash<nlohmann::json\>
- std::less<nlohmann::value_t\>
- std::swap<nlohmann::json\>
