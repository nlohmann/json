# <small>nlohmann::basic_json::</small>push_back

```cpp
// (1)
void push_back(basic_json&& val);
void push_back(const basic_json& val);

// (2)
void push_back(const typename object_t::value_type& val);

// (3)
void push_back(initializer_list_t init);
```

1. Appends the given element `val` to the end of the JSON array. If the function is called on a JSON null value, an
   empty array is created before appending `val`.

2. Inserts the given element `val` to the JSON object. If the function is called on a JSON null value, an empty object
   is created before inserting `val`.

3. This function allows using `push_back` with an initializer list. In case

    1. the current value is an object,
    2. the initializer list `init` contains only two elements, and
    3. the first element of `init` is a string,

    `init` is converted into an object element and added using `push_back(const typename object_t::value_type&)`.
    Otherwise, `init` is converted to a JSON value and added using `push_back(basic_json&&)`.

## Iterator invalidation

For all cases where an element is added to an **array**, a reallocation can happen, in which case all iterators (including
the [`end()`](end.md) iterator) and all references to the elements are invalidated. Otherwise, only the
[`end()`](end.md) iterator is invalidated.

For [`ordered_json`](../ordered_json.md), also adding an element to an **object** can yield a reallocation which again
invalidates all iterators and all references.

## Parameters

`val` (in)
:   the value to add to the JSON array/object

`init` (in)
:   an initializer list

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes to any JSON value. As an exception, a `#!json null`
value is converted to an empty array or object before the element is added and keeps that type if adding the element
throws.

## Exceptions

1. Throws [`type_error.308`](../../home/exceptions.md#jsonexceptiontype_error308) when called on a type other than
   JSON array or null; example: `"cannot use push_back() with number"`
2. Throws [`type_error.308`](../../home/exceptions.md#jsonexceptiontype_error308) when called on a type other than
   JSON object or null; example: `"cannot use push_back() with number"`
3. Throws [`type_error.308`](../../home/exceptions.md#jsonexceptiontype_error308) when called on a type other than
   JSON array or null; example: `"cannot use push_back() with number"`

## Complexity

1. Amortized constant.
2. Logarithmic in the size of the container, O(log(`size()`)).
3. Linear in the size of the initializer list `init`.

## Notes

(3) This function is required to resolve an ambiguous overload error, because pairs like `{"key", "value"}` can be both
    interpreted as `object_t::value_type` or `std::initializer_list<basic_json>`, see
    [#235](https://github.com/nlohmann/json/issues/235) for more information.

## Examples

??? example "Example: (1) add element to array"

    The example shows how `push_back()` and `+=` can be used to add elements to a JSON array. Note how the `null` value
    was silently converted to a JSON array.
    
    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
    int main()
    {
        // create JSON values
        json array = {1, 2, 3, 4, 5};
        json null;
    
        // print values
        std::cout << array << '\n';
        std::cout << null << '\n';
    
        // add values
        array.push_back(6);
        array += 7;
        null += "first";
        null += "second";
    
        // print values
        std::cout << array << '\n';
        std::cout << null << '\n';
    }
    
    ```
    
    Output:
    
    ```json
    [1,2,3,4,5]
    null
    [1,2,3,4,5,6,7]
    ["first","second"]
    
    ```

??? example "Example: (2) add element to object"

    The example shows how `push_back()` and `+=` can be used to add elements to a JSON object. Note how the `null` value
    was silently converted to a JSON object.

    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
    int main()
    {
        // create JSON values
        json object = {{"one", 1}, {"two", 2}};
        json null;
    
        // print values
        std::cout << object << '\n';
        std::cout << null << '\n';
    
        // add values
        object.push_back(json::object_t::value_type("three", 3));
        object += json::object_t::value_type("four", 4);
        null += json::object_t::value_type("A", "a");
        null += json::object_t::value_type("B", "b");
    
        // print values
        std::cout << object << '\n';
        std::cout << null << '\n';
    }
    
    ```
    
    Output:
    
    ```json
    {"one":1,"two":2}
    null
    {"four":4,"one":1,"three":3,"two":2}
    {"A":"a","B":"b"}
    
    ```

??? example "Example: (3) add to object from initializer list"

    The example shows how initializer lists are treated as objects when possible.

    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
    int main()
    {
        // create JSON values
        json object = {{"one", 1}, {"two", 2}};
        json null;
    
        // print values
        std::cout << object << '\n';
        std::cout << null << '\n';
    
        // add values:
        object.push_back({"three", 3});  // object is extended
        object += {"four", 4};           // object is extended
        null.push_back({"five", 5});     // null is converted to array
    
        // print values
        std::cout << object << '\n';
        std::cout << null << '\n';
    
        // would throw:
        //object.push_back({1, 2, 3});
    }
    
    ```
    
    Output:
    
    ```json
    {"one":1,"two":2}
    null
    {"four":4,"one":1,"three":3,"two":2}
    [["five",5]]
    
    ```

## See also

- [`emplace_back`](emplace_back.md) - add a value to an array
- [`operator+=`](operator+=.md) - add a value to an array/object
- [Modifying values](../../features/modifying_values.md) - the article on modifying values

## Version history

1. Added in version 1.0.0.
2. Added in version 1.0.0.
3. Added in version 2.0.0.
