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

Select a pointer (or a node of the tree) to walk it through this document; each segment of the pointer goes one level
deeper. The table below lists the same pointers.

<div class="nj-pointer-walk" data-nj-pointer-walk data-doc="{&quot;array&quot;:[&quot;A&quot;,&quot;B&quot;,&quot;C&quot;],&quot;nested&quot;:{&quot;one&quot;:1,&quot;two&quot;:2,&quot;three&quot;:[true,false]}}" role="group" aria-label="Pointer walker for the example document">
<p class="nj-pointer-static">Highlighted: the path of the pointer <code>/nested/three/1</code>, which identifies <code>false</code>.</p>
<ul class="nj-pointer-tree">
<li data-p="" class="is-on"><span class="nj-pointer-n"><span class="nj-pointer-k">root</span> <span class="nj-pointer-t">object</span></span>
    <ul>
        <li data-p="/array" class="is-pass"><span class="nj-pointer-n"><span class="nj-pointer-k">&quot;array&quot;</span> <span class="nj-pointer-t">array</span></span>
            <ul>
                <li data-p="/array/0"><span class="nj-pointer-n"><span class="nj-pointer-k">0</span>: <span class="nj-pointer-v nj-pointer-v--s">&quot;A&quot;</span></span></li>
                <li data-p="/array/1"><span class="nj-pointer-n"><span class="nj-pointer-k">1</span>: <span class="nj-pointer-v nj-pointer-v--s">&quot;B&quot;</span></span></li>
                <li data-p="/array/2"><span class="nj-pointer-n"><span class="nj-pointer-k">2</span>: <span class="nj-pointer-v nj-pointer-v--s">&quot;C&quot;</span></span></li>
            </ul>
        </li>
        <li data-p="/nested" class="is-on"><span class="nj-pointer-n"><span class="nj-pointer-k">&quot;nested&quot;</span> <span class="nj-pointer-t">object</span></span>
            <ul>
                <li data-p="/nested/one" class="is-pass"><span class="nj-pointer-n"><span class="nj-pointer-k">&quot;one&quot;</span>: <span class="nj-pointer-v nj-pointer-v--n">1</span></span></li>
                <li data-p="/nested/two" class="is-pass"><span class="nj-pointer-n"><span class="nj-pointer-k">&quot;two&quot;</span>: <span class="nj-pointer-v nj-pointer-v--n">2</span></span></li>
                <li data-p="/nested/three" class="is-on"><span class="nj-pointer-n"><span class="nj-pointer-k">&quot;three&quot;</span> <span class="nj-pointer-t">array</span></span>
                    <ul>
                        <li data-p="/nested/three/0" class="is-pass"><span class="nj-pointer-n"><span class="nj-pointer-k">0</span>: <span class="nj-pointer-v nj-pointer-v--b">true</span></span></li>
                        <li data-p="/nested/three/1" class="is-on is-target"><span class="nj-pointer-n"><span class="nj-pointer-k">1</span>: <span class="nj-pointer-v nj-pointer-v--b">false</span></span></li>
                    </ul>
                </li>
            </ul>
        </li>
    </ul>
</li>
</ul>
</div>

<p class="nj-caption" markdown>The highlighted nodes are the path from the root to the selected level, and the line below the tree shows the value the pointer resolves to. Select a segment in the pointer bar to stop at a shallower level, or a node of the tree to select its pointer.</p>

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

To read a value with a fallback, use [`value`](../api/basic_json/value.md) with a JSON Pointer; to test for existence,
use [`contains`](../api/basic_json/contains.md). Neither needs intermediate checks, see
[Nested values](element_access/default_value.md#nested-values).

!!! note "Creating intermediate levels that don't exist"

    See the [`operator[]` notes](../api/basic_json/operator%5B%5D.md#return-value) for how array vs. object is
    decided when a pointer creates intermediate levels that don't exist yet.

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

Each leaf of the document becomes one key of the flat object, and `unflatten()` reverses the mapping:

<div class="nj-fig-wrap" markdown>
--8<-- "images/json_pointer_flatten.svg"
</div>

<p class="nj-caption" markdown>Left: the example document as a tree; right: the flat object it becomes. `flatten()` converts from left to right, `unflatten()` from right to left.</p>

## See also

- [`json_pointer`](../api/json_pointer/index.md) - the JSON Pointer class
- [Nested values](element_access/default_value.md#nested-values) - [`value`](../api/basic_json/value.md),
  [`contains`](../api/basic_json/contains.md), and [`at`](../api/basic_json/at.md) accept JSON Pointers
- [`flatten`](../api/basic_json/flatten.md) - convert a value to an object of JSON Pointers and primitive values
- [`unflatten`](../api/basic_json/unflatten.md) - restore a value from a flattened object
- [JSON Patch](json_patch.md) - paths inside a patch are JSON Pointers
- [JSON Merge Patch](merge_patch.md) - an alternative patch format that does not use JSON Pointer
- [`operator""_json_pointer`](../api/operator_literal_json_pointer.md) - user-defined literal to create a JSON pointer
- [Element Access](element_access/index.md) - other ways to access elements
