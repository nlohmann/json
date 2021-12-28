# Iterators

## Overview

A `basic_json` value is a container and allows access via iterators. Depending on the value type, `basic_json` stores zero or more values.

As for other containers, `begin()` returns an iterator to the first value and `end()` returns an iterator to the value following the last value. The latter iterator is a placeholder and cannot be dereferenced. In case of null values, empty arrays, or empty objects, `begin()` will return `end()`.

![Illustration from cppreference.com](../images/range-begin-end.svg)

### Iteration order for objects

When iterating over objects, values are ordered with respect to the `object_comparator_t` type which defaults to `std::less`. See the [types documentation](types/index.md#key-order) for more information.

??? example

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

### Access object key during iteration

The JSON iterators have two member functions, `key()` and `value()` to access the object key and stored value, respectively. When calling `key()` on a non-object iterator, an [invalid_iterator.207](../home/exceptions.md#jsonexceptioninvalid_iterator207) exception is thrown.

??? example

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

For this reason, the `items()` function allows accessing `iterator::key()` and `iterator::value()` during range-based for loops. In these loops, a reference to the JSON values is returned, so there is no access to the underlying iterator.

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

    Using `items()` on temporary objects is dangerous. Make sure the object's lifetime exceeds the iteration. See <https://github.com/nlohmann/json/issues/2040> for more information.

### Reverse iteration order

`rbegin()` and `rend()` return iterators in the reverse sequence.
    
![Illustration from cppreference.com](../images/range-rbegin-rend.svg)

??? example

    ```cpp
    json j = {1, 2, 3, 4};

    for (auto it = j.begin(); it != j.end(); ++it)
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

Note that "value" means a JSON value in this setting, not values stored in the underlying containers. That is, `*begin()` returns the complete string or binary array and is also safe the underlying string or binary array is empty.

??? example

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
