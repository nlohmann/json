# nlohmann::basic_json::items

```
iteration_proxy<iterator> items() noexcept;
iteration_proxy<const_iterator> items() const noexcept;
```

This function allows accessing `iterator::key()` and `iterator::value()` during range-based for loops. In these loops, a reference to the JSON values is returned, so there is no access to the underlying iterator.

For loop without `items()` function:

```
for (auto it = j_object.begin(); it != j_object.end(); ++it)
{
    std::cout << "key: " << it.key() << ", value:" << it.value() << '\n';
}
```

Range-based for loop without `items()` function:

```
for (auto it : j_object)
{
    // "it" is of type json::reference and has no key() member
    std::cout << "value: " << it << '\n';
}
```

Range-based for loop with `items()` function:

```
for (auto& el : j_object.items())
{
    std::cout << "key: " << el.key() << ", value:" << el.value() << '\n';
}
```

The `items()` function also allows using [structured bindings](https://en.cppreference.com/w/cpp/language/structured_binding) (C++17):

```
for (auto& [key, val] : j_object.items())
{
    std::cout << "key: " << key << ", value:" << val << '\n';
}
```

If you need to name the type of the dereferenced element explicitly (e.g., to write a standalone function that takes it as a parameter, or to use `items()` with `std::for_each`), use `decltype`:

```
using element_type = decltype(*j_object.items().begin());
```

The per-element type (`iteration_proxy_value`) lives in the library's internal `detail` namespace and is intentionally unspecified as a stable, named type -- `decltype` is the supported way to obtain it, but its exact name/definition may change between versions.

## Return value

iteration proxy object wrapping the current value with an interface to use in range-based for loops

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Complexity

Constant.

## Notes

When iterating over an array, `key()` will return the index of the element as string (see example). For primitive types (e.g., numbers), `key()` returns an empty string.

Lifetime issues

Using `items()` on temporary objects is dangerous. Make sure the object's lifetime exceeds the iteration. See [#2040](https://github.com/nlohmann/json/issues/2040) for more information.

## Examples

Example

The following code shows an example for `items()`.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON values
    json j_object = {{"one", 1}, {"two", 2}};
    json j_array = {1, 2, 4, 8, 16};

    // example for an object
    for (auto& x : j_object.items())
    {
        std::cout << "key: " << x.key() << ", value: " << x.value() << '\n';
    }

    // example for an array
    for (auto& x : j_array.items())
    {
        std::cout << "key: " << x.key() << ", value: " << x.value() << '\n';
    }
}
```

Output:

```
key: one, value: 1
key: two, value: 2
key: 0, value: 1
key: 1, value: 2
key: 2, value: 4
key: 3, value: 8
key: 4, value: 16
```

## See also

- [begin](https://json.nlohmann.me/api/basic_json/begin/index.md) returns an iterator to the first element
- [end](https://json.nlohmann.me/api/basic_json/end/index.md) returns an iterator to one past the last element

## Version history

- Added `iterator_wrapper` in version 3.0.0.
- Added `items` and deprecated `iterator_wrapper` in version 3.1.0.
- Added structured binding support in version 3.5.0.

Deprecation

This function replaces the static function `iterator_wrapper` which was introduced in version 1.0.0, but has been deprecated in version 3.1.0. Function `iterator_wrapper` will be removed in version 4.0.0. Please replace all occurrences of `iterator_wrapper(j)` with `j.items()`.

You should be warned by your compiler with a `-Wdeprecated-declarations` warning if you are using a deprecated function.
