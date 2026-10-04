# <small>nlohmann::basic_json::</small>with_t

Member alias templates `with_object_t`, `with_array_t`, `with_string_t`, `with_boolean_t`, `with_integers_t`,
`with_float_t`, `with_allocator_t`, `with_json_serializer_t`, `with_binary_t`, and `with_base_class_t`.

```cpp
template<template<typename, typename, typename...> class ObjectType2>
using with_object_t = basic_json<ObjectType2, ArrayType, StringType, BooleanType,
      NumberIntegerType, NumberUnsignedType, NumberFloatType,
      AllocatorType, JSONSerializer, BinaryType, CustomBaseClass>;

template<template<typename, typename...> class ArrayType2>
using with_array_t = basic_json<ObjectType, ArrayType2, StringType, BooleanType,
      NumberIntegerType, NumberUnsignedType, NumberFloatType,
      AllocatorType, JSONSerializer, BinaryType, CustomBaseClass>;

template<class StringType2>
using with_string_t = basic_json<ObjectType, ArrayType, StringType2, BooleanType,
      NumberIntegerType, NumberUnsignedType, NumberFloatType,
      AllocatorType, JSONSerializer, BinaryType, CustomBaseClass>;

template<class BooleanType2>
using with_boolean_t = basic_json<ObjectType, ArrayType, StringType, BooleanType2,
      NumberIntegerType, NumberUnsignedType, NumberFloatType,
      AllocatorType, JSONSerializer, BinaryType, CustomBaseClass>;

template<class NumberIntegerType2, class NumberUnsignedType2>
using with_integers_t = basic_json<ObjectType, ArrayType, StringType, BooleanType,
      NumberIntegerType2, NumberUnsignedType2, NumberFloatType,
      AllocatorType, JSONSerializer, BinaryType, CustomBaseClass>;

template<class NumberFloatType2>
using with_float_t = basic_json<ObjectType, ArrayType, StringType, BooleanType,
      NumberIntegerType, NumberUnsignedType, NumberFloatType2,
      AllocatorType, JSONSerializer, BinaryType, CustomBaseClass>;

template<template<typename> class AllocatorType2>
using with_allocator_t = basic_json<ObjectType, ArrayType, StringType, BooleanType,
      NumberIntegerType, NumberUnsignedType, NumberFloatType,
      AllocatorType2, JSONSerializer, BinaryType, CustomBaseClass>;

template<template<typename, typename = void> class JSONSerializer2>
using with_json_serializer_t = basic_json<ObjectType, ArrayType, StringType, BooleanType,
      NumberIntegerType, NumberUnsignedType, NumberFloatType,
      AllocatorType, JSONSerializer2, BinaryType, CustomBaseClass>;

template<class BinaryType2>
using with_binary_t = basic_json<ObjectType, ArrayType, StringType, BooleanType,
      NumberIntegerType, NumberUnsignedType, NumberFloatType,
      AllocatorType, JSONSerializer, BinaryType2, CustomBaseClass>;

template<class CustomBaseClass2>
using with_base_class_t = basic_json<ObjectType, ArrayType, StringType, BooleanType,
      NumberIntegerType, NumberUnsignedType, NumberFloatType,
      AllocatorType, JSONSerializer, BinaryType, CustomBaseClass2>;
```

These member alias templates make it easier to create a `basic_json` type that is identical to the current type except
for one (or, in the case of `with_integers_t`, two) of its [template parameters](index.md#template-parameters).
Spelling out all 11 template parameters of `basic_json` just to change a single one is verbose and error-prone; these
aliases only require the replacement type(s).

with_object_t&lt;ObjectType2&gt;
:   replaces `ObjectType`

with_array_t&lt;ArrayType2&gt;
:   replaces `ArrayType`

with_string_t&lt;StringType2&gt;
:   replaces `StringType`

with_boolean_t&lt;BooleanType2&gt;
:   replaces `BooleanType`

with_integers_t&lt;NumberIntegerType2, NumberUnsignedType2&gt;
:   replaces both `NumberIntegerType` and `NumberUnsignedType`; the two are combined into a single alias because they
    are usually changed together (for instance, when switching to fixed-width integer types)

with_float_t&lt;NumberFloatType2&gt;
:   replaces `NumberFloatType`

with_allocator_t&lt;AllocatorType2&gt;
:   replaces `AllocatorType`

with_json_serializer_t&lt;JSONSerializer2&gt;
:   replaces `JSONSerializer`

with_binary_t&lt;BinaryType2&gt;
:   replaces `BinaryType`

with_base_class_t&lt;CustomBaseClass2&gt;
:   replaces `CustomBaseClass`; see also [`json_base_class_t`](json_base_class_t.md)

## Notes

All other template parameters are kept unchanged, so the resulting type still uses, for instance, the same
`ObjectType` unless `with_object_t` itself is used.

## Examples

??? example

    The following code shows how `with_object_t` can be used to create a JSON type that stores object elements in a
    `std::map` and therefore keeps them sorted by key, unlike the default type which preserves insertion order
    only when `nlohmann::ordered_json` is used.

    ```cpp
    --8<-- "examples/with_t.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/with_t.output"
    ```

## See also

- [basic_json](index.md#template-parameters) - the template parameters that can be replaced
- [json_base_class_t](json_base_class_t.md) - the type used for `CustomBaseClass`

## Version history

- Added in version 3.13.0.
