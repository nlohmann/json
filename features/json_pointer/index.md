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

Select a pointer (or a node of the tree) to walk it through this document; each segment of the pointer goes one level deeper. The table below lists the same pointers.

Highlighted: the path of the pointer `/nested/three/1`, which identifies `false`.

- root object
  - "array" array
    - 0: "A"
    - 1: "B"
    - 2: "C"
  - "nested" object
    - "one": 1
    - "two": 2
    - "three" array
      - 0: true
      - 1: false

The highlighted nodes are the path from the root to the selected level, and the line below the tree shows the value the pointer resolves to. Select a segment in the pointer bar to stop at a shallower level, or a node of the tree to select its pointer.

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

[RFC 6901, section 4](https://tools.ietf.org/html/rfc6901#section-4) states that evaluation fails if an object has non-unique member names. A `basic_json` object holds one value per key (see [`object_t`](https://json.nlohmann.me/api/basic_json/object_t/index.md) for how duplicate keys are handled while parsing), so evaluating a JSON Pointer never encounters duplicates.

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

URI fragment representation

[RFC 6901, section 6](https://tools.ietf.org/html/rfc6901#section-6) also defines a URI fragment identifier representation (`#/a%20b`). It is not supported: `json::json_pointer("#/a")` throws [`parse_error.107`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error107). Strip the leading `#` and percent-decode the remainder before creating the JSON pointer.

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

To read a value with a fallback, use [`value`](https://json.nlohmann.me/api/basic_json/value/index.md) with a JSON Pointer; to test for existence, use [`contains`](https://json.nlohmann.me/api/basic_json/contains/index.md). Neither needs intermediate checks, see [Nested values](https://json.nlohmann.me/features/element_access/default_value/#nested-values).

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

Each leaf of the document becomes one key of the flat object, and `unflatten()` reverses the mapping:

Left: the example document as a tree; right: the flat object it becomes. `flatten()` converts from left to right, `unflatten()` from right to left.

## See also

- [`json_pointer`](https://json.nlohmann.me/api/json_pointer/index.md) - the JSON Pointer class
- [Nested values](https://json.nlohmann.me/features/element_access/default_value/#nested-values) - [`value`](https://json.nlohmann.me/api/basic_json/value/index.md), [`contains`](https://json.nlohmann.me/api/basic_json/contains/index.md), and [`at`](https://json.nlohmann.me/api/basic_json/at/index.md) accept JSON Pointers
- [`flatten`](https://json.nlohmann.me/api/basic_json/flatten/index.md) - convert a value to an object of JSON Pointers and primitive values
- [`unflatten`](https://json.nlohmann.me/api/basic_json/unflatten/index.md) - restore a value from a flattened object
- [JSON Patch](https://json.nlohmann.me/features/json_patch/index.md) - paths inside a patch are JSON Pointers
- [JSON Merge Patch](https://json.nlohmann.me/features/merge_patch/index.md) - an alternative patch format that does not use JSON Pointer
- [`operator""_json_pointer`](https://json.nlohmann.me/api/operator_literal_json_pointer/index.md) - user-defined literal to create a JSON pointer
- [Element Access](https://json.nlohmann.me/features/element_access/index.md) - other ways to access elements
