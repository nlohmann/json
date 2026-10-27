# Iterators

## Overview

A `basic_json` value is a container and allows access via iterators. Depending on the value type, `basic_json` stores zero or more values.

As for other containers, [`begin()`](../api/basic_json/begin.md) returns an iterator to the first value and
[`end()`](../api/basic_json/end.md) returns an iterator to the value following the last value. The latter iterator is a
placeholder and cannot be dereferenced. In case of null values, empty arrays, or empty objects, `begin()` will return
`end()`.

<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-fig--range" viewBox="0 0 600 150" role="img" aria-labelledby="fig-be-title" xmlns="http://www.w3.org/2000/svg">
<title id="fig-be-title">A row of fifteen elements followed by a dashed past-the-last position. begin() points to the first element and end() points to the past-the-last position.</title>
<defs><marker id="fig-be-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path class="fg-head" d="M0 1 L10 5 L0 9 z"/></marker></defs>
<rect class="fg-cell" x="30" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="64" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="98" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="132" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="166" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="200" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="234" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="268" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="302" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="336" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="370" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="404" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="438" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="472" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="506" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell fg-cell--end" x="540" y="62" width="30" height="30" rx="5"/>
<rect class="fg-pill" x="15" y="8" width="60" height="24" rx="6"/>
<text class="fg-pilltext" x="45" y="24">begin</text>
<line class="fg-arrow" x1="45" y1="32" x2="45" y2="60" marker-end="url(#fig-be-arrow)"/>
<rect class="fg-pill" x="531" y="8" width="48" height="24" rx="6"/>
<text class="fg-pilltext" x="555" y="24">end</text>
<line class="fg-arrow" x1="555" y1="32" x2="555" y2="60" marker-end="url(#fig-be-arrow)"/>
<text class="fg-note fg-note--r" x="537" y="132">Past-the-last element</text>
<line class="fg-arrow" x1="555" y1="124" x2="555" y2="96" marker-end="url(#fig-be-arrow)"/>
</svg>

</div>

<p class="nj-caption" markdown>The range of `begin()` and `end()`: `begin()` refers to the first element, `end()` to the position after the last element, which must not be dereferenced.</p>

### Iteration order for objects

When iterating over objects, values are ordered with respect to the `object_comparator_t` type which defaults to `std::less`. See the [types documentation](types/index.md#key-order) for more information.

??? example "Example: iteration order of object values"

    ```cpp
    // create JSON object {"one": 1, "two": 2, "three": 3}
    json j;
    j["one"] = 1;
    j["two"] = 2;
    j["three"] = 3;
    
    for (auto it = j.begin(); it != j.end(); ++it)
    {
        std::cout << *it << std::endl;
    }
    ```
    
    Output:
    
    ```json
    1
    3
    2
    ```
    
    The reason for the order is the lexicographic ordering of the object keys "one", "three", "two".

### Access object keys during iteration

The JSON iterators have two member functions, `key()` and `value()` to access the object key and stored value, respectively. When calling `key()` on a non-object iterator, an [invalid_iterator.207](../home/exceptions.md#jsonexceptioninvalid_iterator207) exception is thrown.

??? example "Example: access object keys with `key()` and `value()`"

    ```cpp
    // create JSON object {"one": 1, "two": 2, "three": 3}
    json j;
    j["one"] = 1;
    j["two"] = 2;
    j["three"] = 3;
    
    for (auto it = j.begin(); it != j.end(); ++it)
    {
        std::cout << it.key() << " : " << it.value() << std::endl;
    }
    ```
    
    Output:
    
    ```json
    one : 1
    three : 3
    two : 2
    ```

### Range-based for loops

C++11 allows using range-based for loops to iterate over a container.

```cpp
for (auto it : j_object)
{
    // "it" is of type json::reference and has no key() member
    std::cout << "value: " << it << '\n';
}
```

For this reason, the [`items()`](../api/basic_json/items.md) function allows accessing `iterator::key()` and
`iterator::value()` during range-based for loops. In these loops, a reference to the JSON values is returned, so there
is no access to the underlying iterator.

```cpp
for (auto& el : j_object.items())
{
    std::cout << "key: " << el.key() << ", value:" << el.value() << '\n';
}
```

The items() function also allows using structured bindings (C++17):

```cpp
for (auto& [key, val] : j_object.items())
{
    std::cout << "key: " << key << ", value:" << val << '\n';
}
```

!!! note

    When iterating over an array, `key()` will return the index of the element as string. For primitive types (e.g., numbers), `key()` returns an empty string.
    
!!! warning

    Using `items()` on temporary objects is dangerous. Make sure the object's lifetime exceeds the iteration. See [#2040](https://github.com/nlohmann/json/issues/2040) for more information.

### Reverse iteration order

[`rbegin()`](../api/basic_json/rbegin.md) and [`rend()`](../api/basic_json/rend.md) return iterators in the reverse
sequence.
    
<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-fig--range" viewBox="0 0 600 236" role="img" aria-labelledby="fig-rbe-title" xmlns="http://www.w3.org/2000/svg">
<title id="fig-rbe-title">Two rows of sixteen cells. The upper row shows the reversed sequence: rend() points to a dashed position before the first element and rbegin() to the last element. The lower row shows the forward sequence: begin() points to the first element and end() to a dashed position after the last element. A reverse iterator stores an iterator to the next element, so rend() corresponds to begin() and rbegin() to end().</title>
<defs><marker id="fig-rbe-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path class="fg-head" d="M0 1 L10 5 L0 9 z"/></marker></defs>
<rect class="fg-cell fg-cell--end" x="30" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="64" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="98" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="132" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="166" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="200" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="234" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="268" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="302" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="336" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="370" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="404" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="438" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="472" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="506" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="540" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="30" y="144" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="64" y="144" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="98" y="144" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="132" y="144" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="166" y="144" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="200" y="144" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="234" y="144" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="268" y="144" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="302" y="144" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="336" y="144" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="370" y="144" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="404" y="144" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="438" y="144" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="472" y="144" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="506" y="144" width="30" height="30" rx="5"/>
<rect class="fg-cell fg-cell--end" x="540" y="144" width="30" height="30" rx="5"/>
<rect class="fg-pill" x="19" y="8" width="52" height="24" rx="6"/>
<text class="fg-pilltext" x="45" y="24">rend</text>
<line class="fg-arrow" x1="45" y1="32" x2="45" y2="60" marker-end="url(#fig-rbe-arrow)"/>
<rect class="fg-pill" x="521" y="8" width="68" height="24" rx="6"/>
<text class="fg-pilltext" x="555" y="24">rbegin</text>
<line class="fg-arrow" x1="555" y1="32" x2="555" y2="60" marker-end="url(#fig-rbe-arrow)"/>
<text class="fg-note fg-note--l" x="81" y="24">Reverse past-the-last element</text>
<line class="fg-arrow fg-arrow--dash" x1="45" y1="94" x2="45" y2="142"/>
<line class="fg-arrow fg-arrow--dash" x1="555" y1="94" x2="555" y2="142"/>
<text class="fg-note" x="300" y="123">A reverse iterator stores an iterator to the next element</text>
<text class="fg-note" x="300" y="141" dy="0" style="display:none"></text>
<rect class="fg-pill" x="15" y="204" width="60" height="24" rx="6"/>
<text class="fg-pilltext" x="45" y="220">begin</text>
<line class="fg-arrow" x1="45" y1="202" x2="45" y2="178" marker-end="url(#fig-rbe-arrow)"/>
<rect class="fg-pill" x="531" y="204" width="48" height="24" rx="6"/>
<text class="fg-pilltext" x="555" y="220">end</text>
<line class="fg-arrow" x1="555" y1="202" x2="555" y2="178" marker-end="url(#fig-rbe-arrow)"/>
<text class="fg-note fg-note--r" x="515" y="221">Past-the-last element</text>
</svg>

</div>

<p class="nj-caption" markdown>The range of `rbegin()` and `rend()` over the same elements: `rbegin()` refers to the last element and `rend()` to the position before the first one. Each reverse iterator stores an iterator to the element after the one it refers to.</p>

??? example "Example: reverse iteration with `rbegin()` and `rend()`"

    ```cpp
    json j = {1, 2, 3, 4};

    for (auto it = j.rbegin(); it != j.rend(); ++it)
    {
        std::cout << *it << std::endl;
    }
    ```
    
    Output:
    
    ```json
    4
    3
    2
    1
    ```

### Iterating strings and binary values

Note that "value" means a JSON value in this setting, not values stored in the underlying containers. That is, `*begin()` returns the complete string or binary array and is also safe if the underlying string or binary array is empty.

??? example "Example: iterate over a string value"

    ```cpp
    json j = "Hello, world";
    for (auto it = j.begin(); it != j.end(); ++it)
    {
        std::cout << *it << std::endl;
    }
    ```
    
    Output:
    
    ```json
    "Hello, world"
    ```

## Iterator invalidation

| Operations | invalidated iterators |
|------------|-----------------------|
| `clear`    | all                   |

## See also

- [`begin`](../api/basic_json/begin.md) - / [`end`](../api/basic_json/end.md) - iterators to the first and one past the last element
- [`rbegin`](../api/basic_json/rbegin.md) - / [`rend`](../api/basic_json/rend.md) - reverse iterators
- [`cbegin`](../api/basic_json/cbegin.md) - / [`cend`](../api/basic_json/cend.md) - const iterators
- [`items`](../api/basic_json/items.md) - iterate over keys and values
- [Object Order](object_order.md) - iteration order of object keys
- [Element Access](element_access/index.md) - access single elements
- [Modifying values](modifying_values.md) - add and remove elements (including iterator invalidation rules)
