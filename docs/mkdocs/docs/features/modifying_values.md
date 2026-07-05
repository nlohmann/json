# Modifying values

Once a JSON value exists, its content can be changed: elements can be added, replaced, merged, and removed. This page
gives an overview of the available operations. For read access, see [element access](element_access/index.md).

## Adding to arrays

New elements are appended to an array with [`push_back`](../api/basic_json/push_back.md) or constructed in place with
[`emplace_back`](../api/basic_json/emplace_back.md). If the value is `#!json null`, it is converted to an array first, so
these functions can also be used to build an array from scratch.

```cpp
json j;                 // null
j.push_back(1);         // [1]
j.push_back(2);         // [1,2]
j.emplace_back(3);      // [1,2,3]

// operator+= is a shorthand for push_back
j += 4;                 // [1,2,3,4]
```

## Adding to objects

The most common way to add or replace a member is [`operator[]`](element_access/unchecked_access.md), which inserts the
key if it does not exist yet:

```cpp
json j;
j["name"] = "Mary";     // {"name":"Mary"}
j["name"] = "John";     // {"name":"John"}  (replaced)
```

[`emplace`](../api/basic_json/emplace.md) inserts a member only if the key is not already present, and reports whether
the insertion happened — useful for "add if absent" semantics.

## Merging objects

To merge one object into another, [`update`](../api/basic_json/update.md) copies all members from another object,
overwriting existing keys (similar to Python's `dict.update`). This is the idiomatic way to combine two objects.

??? example

    ```cpp
    --8<-- "examples/update.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/update.output"
    ```

For a recursive merge that follows [RFC 7386](https://tools.ietf.org/html/rfc7386), see
[JSON Merge Patch](merge_patch.md). To apply a sequence of well-defined edit operations, see
[JSON Patch](json_patch.md).

## Removing elements

Elements are removed with [`erase`](../api/basic_json/erase.md), which accepts an object key, an array index, or an
iterator. [`clear`](../api/basic_json/clear.md) empties a value while keeping its type, and
[`operator[]`](element_access/unchecked_access.md) combined with assignment can overwrite a value entirely.

```cpp
json j = {{"a", 1}, {"b", 2}, {"c", 3}};
j.erase("b");           // {"a":1,"c":3}

json a = {1, 2, 3, 4};
a.erase(1);             // [1,3,4]  (erase by index)
```

## See also

- [`push_back`](../api/basic_json/push_back.md) / [`emplace_back`](../api/basic_json/emplace_back.md) - append to an array
- [`emplace`](../api/basic_json/emplace.md) - insert into an object if the key is absent
- [`update`](../api/basic_json/update.md) - merge objects
- [`erase`](../api/basic_json/erase.md) / [`clear`](../api/basic_json/clear.md) - remove elements
- [JSON Patch and Diff](json_patch.md) and [JSON Merge Patch](merge_patch.md) - structured modifications
