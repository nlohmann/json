# nlohmann::basic_json_view

Defined in header `<nlohmann/json_view.hpp>`

```
template<typename BasicJsonType, view_mode Mode = view_mode::read_only>
class basic_json_view;
```

A read-only handle to one value of a [`basic_json_document`](https://json.nlohmann.me/api/basic_json_document/index.md): two pointers (a pointer to the document and a pointer into its index), trivially copyable. A view is valid as long as

- the document is alive,
- the document has not been re-parsed with [`read()`](https://json.nlohmann.me/api/basic_json_document/read/index.md) (or [`parse()`](https://json.nlohmann.me/api/basic_json_document/parse/index.md) into it) or shrunk with [`shrink_to_fit()`](https://json.nlohmann.me/api/basic_json_document/shrink_to_fit/index.md) since the view was taken, and
- if the document borrows its source text, that text is still alive and unmodified (floating-point values and unescaped strings are read from it lazily).

Moving the document itself does not invalidate its views: the index is heap-allocated independently of the `basic_json_document` object.

`basic_json_view` provides the read-only part of the `BasicJsonType` interface:

- the type-inspection functions
- element access
- lookup
- iteration
- conversion: [`get<T>()`](https://json.nlohmann.me/api/basic_json_view/get/index.md), [`get_string()`](https://json.nlohmann.me/api/basic_json_view/get_string/index.md), [`number_token()`](https://json.nlohmann.me/api/basic_json_view/number_token/index.md), and [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) to build the `BasicJsonType` value of a subtree on demand
- comparison: [`operator==`](https://json.nlohmann.me/api/basic_json_view/operator_eq/index.md) and [`operator!=`](https://json.nlohmann.me/api/basic_json_view/operator_ne/index.md) compare two views, or a view and a `BasicJsonType` value, without ever building a `BasicJsonType` value for a view; no ordering comparison (`operator<`) is provided

[`operator[]`](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/index.md), [`at`](https://json.nlohmann.me/api/basic_json_view/at/index.md), [`contains`](https://json.nlohmann.me/api/basic_json_view/contains/index.md), and [`value`](https://json.nlohmann.me/api/basic_json_view/value/index.md) also accept a [`json_pointer`](https://json.nlohmann.me/api/json_pointer/index.md). Unlike `basic_json`, there are no implicit conversion operators (no `operator ValueType()`), and no `get_ptr()` or `get_ref()`; see [`get`](https://json.nlohmann.me/api/basic_json_view/get/index.md).

`basic_json_view` itself is always read-only -- it never has a `set` or `push_back` of its own. A view of an **editable** document (`view_mode::editable`) sees every edit made through [`basic_json_document::set`](https://json.nlohmann.me/api/basic_json_document/set/index.md) and [`basic_json_document::push_back`](https://json.nlohmann.me/api/basic_json_document/push_back/index.md): once a value is changed, every view that still refers to it -- including ones taken before the change -- reads the new value. See [Edits](https://json.nlohmann.me/api/basic_json_document/#edits).

## Template parameters

`BasicJsonType` : a specialization of [`basic_json`](https://json.nlohmann.me/api/basic_json/index.md), matching the [`basic_json_document`](https://json.nlohmann.me/api/basic_json_document/index.md) the view was taken from.

`Mode` : a [`view_mode`](https://json.nlohmann.me/api/view_mode/index.md): whether the view is of an editable document, matching the [`basic_json_document`](https://json.nlohmann.me/api/basic_json_document/index.md) it was taken from (optional, `view_mode::read_only` by default). See [Edits](https://json.nlohmann.me/api/basic_json_document/#edits).

## Specializations

- [**json_view**](https://json.nlohmann.me/api/json_view/index.md) - views of a [`json_document`](https://json.nlohmann.me/api/json_document/index.md)
- [**ordered_json_view**](https://json.nlohmann.me/api/ordered_json_view/index.md) - views of an [`ordered_json_document`](https://json.nlohmann.me/api/ordered_json_document/index.md)
- [**json_editable_view**](https://json.nlohmann.me/api/json_editable_view/index.md) - views of a [`json_editable_document`](https://json.nlohmann.me/api/json_editable_document/index.md)
- [**ordered_json_editable_view**](https://json.nlohmann.me/api/ordered_json_editable_view/index.md) - views of an [`ordered_json_editable_document`](https://json.nlohmann.me/api/ordered_json_editable_document/index.md)

## Member types

- **basic_json_type** - `BasicJsonType` (it also marks the class for [`is_json_view`](https://json.nlohmann.me/api/is_json_view/index.md))
- **value_t** - the JSON type enumeration, see [`basic_json::value_t`](https://json.nlohmann.me/api/basic_json/value_t/index.md)
- **string_t**, **number_integer_t**, **number_unsigned_t**, **number_float_t**, **json_pointer** - the corresponding member types of `BasicJsonType`
- **size_type** - `std::size_t`
- **string_view_t** - `std::string_view` on C++17 and newer, a minimal internal substitute otherwise
- **iterator**, **const_iterator** - a forward iterator over the elements of an array or the member values of an object, in document order; both names refer to the same type, since a view is always read-only
- [**number_format**](https://json.nlohmann.me/api/basic_json_view/number_format/index.md) - how [`dump()`](https://json.nlohmann.me/api/basic_json_view/dump/index.md) writes numbers

## Member functions

- [(constructor)](https://json.nlohmann.me/api/basic_json_view/basic_json_view/index.md)

### Object inspection

- [**type**](https://json.nlohmann.me/api/basic_json_view/type/index.md) - return the type of the value
- [**type_name**](https://json.nlohmann.me/api/basic_json_view/type_name/index.md) - return the type as string
- [**is_null**](https://json.nlohmann.me/api/basic_json_view/is_null/index.md) - return whether the value is null
- [**is_boolean**](https://json.nlohmann.me/api/basic_json_view/is_boolean/index.md) - return whether the value is a boolean
- [**is_number**](https://json.nlohmann.me/api/basic_json_view/is_number/index.md) - return whether the value is a number
- [**is_number_integer**](https://json.nlohmann.me/api/basic_json_view/is_number_integer/index.md) - return whether the value is an integer number
- [**is_number_unsigned**](https://json.nlohmann.me/api/basic_json_view/is_number_unsigned/index.md) - return whether the value is an unsigned integer number
- [**is_number_float**](https://json.nlohmann.me/api/basic_json_view/is_number_float/index.md) - return whether the value is a floating-point number
- [**is_string**](https://json.nlohmann.me/api/basic_json_view/is_string/index.md) - return whether the value is a string
- [**is_array**](https://json.nlohmann.me/api/basic_json_view/is_array/index.md) - return whether the value is an array
- [**is_object**](https://json.nlohmann.me/api/basic_json_view/is_object/index.md) - return whether the value is an object
- [**is_binary**](https://json.nlohmann.me/api/basic_json_view/is_binary/index.md) - return whether the value is a binary array (always `false`)
- [**is_primitive**](https://json.nlohmann.me/api/basic_json_view/is_primitive/index.md) - return whether the type is primitive
- [**is_structured**](https://json.nlohmann.me/api/basic_json_view/is_structured/index.md) - return whether the type is structured
- [**is_discarded**](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md) - return whether the view is invalid

### Element access

- [**at**](https://json.nlohmann.me/api/basic_json_view/at/index.md) - access specified element with bounds checking
- [**operator[]**](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/index.md) - access specified element
- [**value**](https://json.nlohmann.me/api/basic_json_view/value/index.md) - access specified element with default value
- [**front**](https://json.nlohmann.me/api/basic_json_view/front/index.md) - access the first element
- [**back**](https://json.nlohmann.me/api/basic_json_view/back/index.md) - access the last element

### Lookup

- [**find**](https://json.nlohmann.me/api/basic_json_view/find/index.md) - find an element in an object
- [**count**](https://json.nlohmann.me/api/basic_json_view/count/index.md) - returns the number of occurrences of a key in an object
- [**contains**](https://json.nlohmann.me/api/basic_json_view/contains/index.md) - check the existence of an element in an object

### Iterators

- [**begin**](https://json.nlohmann.me/api/basic_json_view/begin/index.md) - returns an iterator to the first element
- [**cbegin**](https://json.nlohmann.me/api/basic_json_view/cbegin/index.md) - returns a const iterator to the first element
- [**end**](https://json.nlohmann.me/api/basic_json_view/end/index.md) - returns an iterator to one past the last element
- [**cend**](https://json.nlohmann.me/api/basic_json_view/cend/index.md) - returns a const iterator to one past the last element
- [**items**](https://json.nlohmann.me/api/basic_json_view/items/index.md) - wrapper to access iterator member functions in range-based for

### Capacity

- [**size**](https://json.nlohmann.me/api/basic_json_view/size/index.md) - return the number of elements
- [**empty**](https://json.nlohmann.me/api/basic_json_view/empty/index.md) - return whether the value has no elements

### Conversion

- [**get**](https://json.nlohmann.me/api/basic_json_view/get/index.md) - get a value
- [**get_to**](https://json.nlohmann.me/api/basic_json_view/get_to/index.md) - get a value and write it to a destination
- [**get_string**](https://json.nlohmann.me/api/basic_json_view/get_string/index.md) - get a string value without a copy
- [**number_token**](https://json.nlohmann.me/api/basic_json_view/number_token/index.md) - get a number's token text without a copy
- [**materialize**](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) - build the `BasicJsonType` value of this subtree

### Comparison

- [**operator==**](https://json.nlohmann.me/api/basic_json_view/operator_eq/index.md) - comparison: equal
- [**operator!=**](https://json.nlohmann.me/api/basic_json_view/operator_ne/index.md) - comparison: not equal

### Serialization

- [**dump**](https://json.nlohmann.me/api/basic_json_view/dump/index.md) - serialize to a JSON-formatted string
- [**operator\<<**](https://json.nlohmann.me/api/basic_json_view/operator_ltlt/index.md) - serialize to stream

### Source access

- [**source_offset**](https://json.nlohmann.me/api/basic_json_view/source_offset/index.md) - byte offset of this value in the document's source text

## See also

- [Zero-copy JSON views](https://json.nlohmann.me/features/json_view/index.md) - guide to documents and views
- [**basic_json_document**](https://json.nlohmann.me/api/basic_json_document/index.md) - the document that owns the parsed data
- [**json_view**](https://json.nlohmann.me/api/json_view/index.md) and [**json_editable_view**](https://json.nlohmann.me/api/json_editable_view/index.md) - the default specializations
- [**materialize**](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) - build a `basic_json` value from a view

## Version history

- Added in version 3.13.0 unreleased.
