# <small>nlohmann::</small>basic_json_view

<small>Defined in header `<nlohmann/json_view.hpp>`</small>

```cpp
template<typename BasicJsonType>
class basic_json_view;
```

A read-only handle to one value of a [`basic_json_document`](../basic_json_document/index.md): two pointers (a pointer
to the document and a pointer into its index), trivially copyable. A view is valid as long as

- the document is alive,
- the document has not been re-parsed with [`read()`](../basic_json_document/read.md) (or
  [`parse()`](../basic_json_document/parse.md) into it) or shrunk with
  [`shrink_to_fit()`](../basic_json_document/shrink_to_fit.md) since the view was taken, and
- if the document borrows its source text, that text is still alive.

Moving the document itself does not invalidate its views: the index is heap-allocated independently of the
`basic_json_document` object.

`basic_json_view` provides the read-only part of the `BasicJsonType` interface: the type-inspection functions, element
access, lookup, iteration, conversion, and comparison -- [`get<T>()`](get.md), [`get_string()`](get_string.md),
[`number_token()`](number_token.md), and [`materialize()`](materialize.md) to build the `BasicJsonType` value of a
subtree on demand. [`operator[]`](operator%5B%5D.md), [`at`](at.md), [`contains`](contains.md), and
[`value`](value.md) also accept a [`json_pointer`](../json_pointer/index.md). [`operator==`](operator_eq.md) and
[`operator!=`](operator_ne.md) compare two views, or a view and a `BasicJsonType` value, without ever building a
`BasicJsonType` value for a view; no ordering comparison (`#!cpp operator<`) is provided.

## Template parameters

`BasicJsonType`
:   a specialization of [`basic_json`](../basic_json/index.md), matching the
    [`basic_json_document`](../basic_json_document/index.md) the view was taken from.

## Specializations

- [**json_view**](../json_view.md) - views of a [`json_document`](../json_document.md)
- [**ordered_json_view**](../ordered_json_view.md) - views of an [`ordered_json_document`](../ordered_json_document.md)

## Member types

- **value_t** - the JSON type enumeration, see [`basic_json::value_t`](../basic_json/value_t.md)
- **string_t**, **number_integer_t**, **number_unsigned_t**, **number_float_t**, **json_pointer** - the corresponding
  member types of `BasicJsonType`
- **size_type** - `#!cpp std::size_t`
- **string_view_t** - `#!cpp std::string_view` on C++17 and newer, a minimal internal substitute otherwise
- **iterator**, **const_iterator** - a forward iterator over the elements of an array or the member values of an
  object, in document order; both names refer to the same type, since a view is always read-only
- **item** - a (key, value) pair produced by [`items()`](items.md)
- [**number_format**](number_format.md) - how [`dump()`](dump.md) writes numbers

## Member functions

- [(constructor)](basic_json_view.md)

### Object inspection

- [**type**](type.md) - return the type of the value
- [**type_name**](type_name.md) - return the type as string
- [**is_null**](is_null.md) - return whether the value is null
- [**is_boolean**](is_boolean.md) - return whether the value is a boolean
- [**is_number**](is_number.md) - return whether the value is a number
- [**is_number_integer**](is_number_integer.md) - return whether the value is an integer number
- [**is_number_unsigned**](is_number_unsigned.md) - return whether the value is an unsigned integer number
- [**is_number_float**](is_number_float.md) - return whether the value is a floating-point number
- [**is_string**](is_string.md) - return whether the value is a string
- [**is_array**](is_array.md) - return whether the value is an array
- [**is_object**](is_object.md) - return whether the value is an object
- [**is_binary**](is_binary.md) - return whether the value is a binary array (always `#!cpp false`)
- [**is_primitive**](is_primitive.md) - return whether the type is primitive
- [**is_structured**](is_structured.md) - return whether the type is structured
- [**is_discarded**](is_discarded.md) - return whether the view is invalid
- [**operator bool**](operator_bool.md) - return whether the view refers to a value

### Element access

- [**at**](at.md) - access specified element with bounds checking
- [**operator[]**](operator[].md) - access specified element
- [**value**](value.md) - access specified element with default value
- [**front**](front.md) - access the first element
- [**back**](back.md) - access the last element

### Lookup

- [**find**](find.md) - find an element in an object
- [**count**](count.md) - returns the number of occurrences of a key in an object
- [**contains**](contains.md) - check the existence of an element in an object

### Iterators

- [**begin**](begin.md) - returns an iterator to the first element
- [**cbegin**](cbegin.md) - returns a const iterator to the first element
- [**end**](end.md) - returns an iterator to one past the last element
- [**cend**](cend.md) - returns a const iterator to one past the last element
- [**items**](items.md) - wrapper to access iterator member functions in range-based for

### Capacity

- [**size**](size.md) - return the number of elements
- [**empty**](empty.md) - return whether the value has no elements

### Conversion

- [**get**](get.md) - get a value
- [**get_to**](get_to.md) - get a value and write it to a destination
- [**get_string**](get_string.md) - get a string value without a copy
- [**number_token**](number_token.md) - get a number's token text without a copy
- [**materialize**](materialize.md) - build the `BasicJsonType` value of this subtree

### Comparison

- [**operator==**](operator_eq.md) - comparison: equal
- [**operator!=**](operator_ne.md) - comparison: not equal

### Serialization

- [**dump**](dump.md) - serialize to a JSON-formatted string
- [**operator<<**](operator_ltlt.md) - serialize to stream

### Source access

- [**source_offset**](source_offset.md) - byte offset of this value in the document's source text

## Version history

- Added in version 3.13.0.
