# JSON Pointer

## Introduction

The library supports **JSON Pointer** ([RFC 6901](https://tools.ietf.org/html/rfc6901)) as an alternative means to address structured values. A JSON Pointer is a string that identifies a specific value within a JSON document.

Consider the following JSON document

```
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

| JSON Pointer      | JSON value                                                                |
| ----------------- | ------------------------------------------------------------------------- |
| \`\`              | `{"array":["A","B","C"],"nested":{"one":1,"two":2,"three":[true,false]}}` |
| `/array`          | `["A","B","C"]`                                                           |
| `/array/0`        | `A`                                                                       |
| `/array/1`        | `B`                                                                       |
| `/array/2`        | `C`                                                                       |
| `/nested`         | `{"one":1,"two":2,"three":[true,false]}`                                  |
| `/nested/one`     | `1`                                                                       |
| `/nested/two`     | `2`                                                                       |
| `/nested/three`   | `[true,false]`                                                            |
| `/nested/three/0` | `true`                                                                    |
| `/nested/three/1` | `false`                                                                   |

Note `/` does not identify the root (i.e., the whole document), but an object entry with empty key `""`. See [RFC 6901](https://tools.ietf.org/html/rfc6901) for more information.

## JSON Pointer creation

JSON Pointers can be created from a string:

```
json::json_pointer p("/nested/one");
```

Furthermore, a user-defined string literal can be used to achieve the same result:

```
auto p = "/nested/one"_json_pointer;
```

The escaping rules of [RFC 6901](https://tools.ietf.org/html/rfc6901) are implemented. See the [constructor documentation](https://json.nlohmann.me/api/json_pointer/json_pointer/index.md) for more information.

## Value access

JSON Pointers can be used in the [`at`](https://json.nlohmann.me/api/basic_json/at/index.md), [`operator[]`](https://json.nlohmann.me/api/basic_json/operator%5B%5D/index.md), and [`value`](https://json.nlohmann.me/api/basic_json/value/index.md) functions just like object keys or array indices.

```
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

Creating intermediate levels that don't exist

See the [`operator[]` notes](https://json.nlohmann.me/api/basic_json/operator%5B%5D/#return-value) for how array vs. object is decided when a pointer creates intermediate levels that don't exist yet.

## Flatten / unflatten

The library implements a function [`flatten`](https://json.nlohmann.me/api/basic_json/flatten/index.md) to convert any JSON document into a JSON object where each key is a JSON Pointer and each value is a primitive JSON value (i.e., a string, boolean, number, or null).

```
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

```
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

The reverse function, [`unflatten`](https://json.nlohmann.me/api/basic_json/unflatten/index.md) recreates the original value.

```
auto j_original = j_flat.unflatten();
```

## See also

- Class [`json_pointer`](https://json.nlohmann.me/api/json_pointer/index.md)
- Function [`flatten`](https://json.nlohmann.me/api/basic_json/flatten/index.md)
- Function [`unflatten`](https://json.nlohmann.me/api/basic_json/unflatten/index.md)
- [JSON Patch](https://json.nlohmann.me/features/json_patch/index.md)
