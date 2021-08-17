# basic_json::json_serializer

```cpp
template<typename T, typename SFINAE>
using json_serializer = JSONSerializer<T, SFINAE>;
```

## Template parameters

`T`
:   type to convert; will be used in the `to_json`/`from_json` functions

`SFINAE`
:   type to add compile type checks via SFINAE; usually `#!cpp void`

## Notes

#### Default type

The default values for `json_serializer` is [`adl_serializer`](../adl_serializer.md).

## Version history

- Since version 2.0.0.
