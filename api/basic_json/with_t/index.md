# nlohmann::basic_json::with_t

Member alias templates `with_object_t`, `with_array_t`, `with_string_t`, `with_boolean_t`, `with_integers_t`, `with_float_t`, `with_allocator_t`, `with_json_serializer_t`, `with_binary_t`, and `with_base_class_t`.

```
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

These member alias templates make it easier to create a `basic_json` type that is identical to the current type except for one (or, in the case of `with_integers_t`, two) of its [template parameters](https://json.nlohmann.me/api/basic_json/#template-parameters). Spelling out all 11 template parameters of `basic_json` just to change a single one is verbose and error-prone; these aliases only require the replacement type(s).

with_object_t<ObjectType2> : replaces `ObjectType`

with_array_t<ArrayType2> : replaces `ArrayType`

with_string_t<StringType2> : replaces `StringType`

with_boolean_t<BooleanType2> : replaces `BooleanType`

with_integers_t\<NumberIntegerType2, NumberUnsignedType2> : replaces both `NumberIntegerType` and `NumberUnsignedType`; the two are combined into a single alias because they are usually changed together (for instance, when switching to fixed-width integer types)

with_float_t<NumberFloatType2> : replaces `NumberFloatType`

with_allocator_t<AllocatorType2> : replaces `AllocatorType`

with_json_serializer_t<JSONSerializer2> : replaces `JSONSerializer`

with_binary_t<BinaryType2> : replaces `BinaryType`

with_base_class_t<CustomBaseClass2> : replaces `CustomBaseClass`; see also [`json_base_class_t`](https://json.nlohmann.me/api/basic_json/json_base_class_t/index.md)

## Notes

All other template parameters are kept unchanged, so the resulting type still uses, for instance, the same `ObjectType` unless `with_object_t` itself is used.

The aliases are members of every `basic_json` specialization, including [`ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md), and the type they produce is again a `basic_json` specialization. They can therefore be chained to replace several template parameters at once:

```
using my_json = nlohmann::json::with_integers_t<int, unsigned int>::with_float_t<float>;
using my_ordered_json = nlohmann::ordered_json::with_string_t<std::wstring>;
```

The result is the same type as spelling out all template parameters, so the order of the chained aliases does not matter. For instance, `nlohmann::json::with_object_t<nlohmann::ordered_map>` is `nlohmann::ordered_json`.

## Examples

Example

The following code shows how `with_object_t` can be used to create a JSON type that stores object elements in a `std::map` and therefore keeps them sorted by key, unlike the default type which preserves insertion order only when `nlohmann::ordered_json` is used.

```
#include <iostream>
#include <map>
#include <nlohmann/json.hpp>

// a JSON type that stores objects in a std::map (which keeps keys sorted)
// instead of the default ordered associative container
using sorted_json = nlohmann::json::with_object_t<std::map>;

int main()
{
    sorted_json j;
    j["c"] = 1;
    j["a"] = 2;
    j["b"] = 3;

    // keys are sorted, because std::map is used to store the object
    std::cout << j.dump() << std::endl;
}
```

Output:

```
{"a":2,"b":3,"c":1}
```

## See also

- [basic_json](https://json.nlohmann.me/api/basic_json/#template-parameters) - the template parameters that can be replaced
- [json_base_class_t](https://json.nlohmann.me/api/basic_json/json_base_class_t/index.md) - the type used for `CustomBaseClass`

## Version history

- Added in version 3.13.0 unreleased.
