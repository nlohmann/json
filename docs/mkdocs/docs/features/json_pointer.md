# JSON Pointer

## Introduction

The library supports **JSON Pointer** ([RFC 6901](https://tools.ietf.org/html/rfc6901)) as an alternative means to
address structured values. A JSON Pointer is a string that identifies a specific value within a JSON document.

Consider the following JSON document

```json
{
    "array": ["A", "B", "C"],
    "nested": {
        "one": 1,
        "two": 2,
        "three": [true, false]
    }
}
```

Then every value inside the JSON document can be identified as follows:

| JSON Pointer      | JSON value                                                                       |
|-------------------|----------------------------------------------------------------------------------|
| ``                | `#!json {"array":["A","B","C"],"nested":{"one":1,"two":2,"three":[true,false]}}` |
| `/array`          | `#!json ["A","B","C"]`                                                           |
| `/array/0`        | `#!json A`                                                                       |
| `/array/1`        | `#!json B`                                                                       |
| `/array/2`        | `#!json C`                                                                       |
| `/nested`         | `#!json {"one":1,"two":2,"three":[true,false]}`                                  |
| `/nested/one`     | `#!json 1`                                                                       |
| `/nested/two`     | `#!json 2`                                                                       |
| `/nested/three`   | `#!json [true,false]`                                                            |
| `/nested/three/0` | `#!json true`                                                                    |
| `/nested/three/1` | `#!json false`                                                                   |

Note `/` does not identify the root (i.e., the whole document), but an object entry with empty key `""`. See
[RFC 6901](https://tools.ietf.org/html/rfc6901) for more information.

## JSON Pointer creation

JSON Pointers can be created from a string:

```cpp
json::json_pointer p("/nested/one");
```

Furthermore, a user-defined string literal can be used to achieve the same result:

```cpp
auto p = "/nested/one"_json_pointer;
```

The escaping rules of [RFC 6901](https://tools.ietf.org/html/rfc6901) are implemented. See the
[constructor documentation](../api/json_pointer/json_pointer.md) for more information.

## Value access

JSON Pointers can be used in the [`at`](../api/basic_json/at.md), [`operator[]`](../api/basic_json/operator%5B%5D.md),
and [`value`](../api/basic_json/value.md) functions just like object keys or array indices.

```cpp
// the JSON value from above
auto j = json::parse(R"({
    "array": ["A", "B", "C"],
    "nested": {
        "one": 1,
        "two": 2,
        "three": [true, false]
    }
})");

// access values
auto val = j[""_json_pointer];                              // {"array":["A","B","C"],...}
auto val1 = j["/nested/one"_json_pointer];                  // 1
auto val2 = j.at(json::json_pointer("/nested/three/1"));    // false
auto val3 = j.value(json::json_pointer("/nested/four"), 0); // 0
```

## Flatten / unflatten

The library implements a function [`flatten`](../api/basic_json/flatten.md) to convert any JSON document into a JSON
object where each key is a JSON Pointer and each value is a primitive JSON value (i.e., a string, boolean, number, or
null).

```cpp
// the JSON value from above
auto j = json::parse(R"({
    "array": ["A", "B", "C"],
    "nested": {
        "one": 1,
        "two": 2,
        "three": [true, false]
    }
})");

// create flattened value
auto j_flat = j.flatten();
```

The resulting value `j_flat` is:

```json
{
  "/array/0": "A",
  "/array/1": "B",
  "/array/2": "C",
  "/nested/one": 1,
  "/nested/two": 2,
  "/nested/three/0": true,
  "/nested/three/1": false
}
```

The reverse function, [`unflatten`](../api/basic_json/unflatten.md) recreates the original value.

```cpp
auto j_original = j_flat.unflatten();
```

## See also

- Class [`json_pointer`](../api/json_pointer/index.md)
- Function [`flatten`](../api/basic_json/flatten.md)
- Function [`unflatten`](../api/basic_json/unflatten.md)
- [JSON Patch](json_patch.md)
