# nlohmann::basic_json::insert

```
// (1)
iterator insert(const_iterator pos, const basic_json& val);
iterator insert(const_iterator pos, basic_json&& val);

// (2)
iterator insert(const_iterator pos, size_type cnt, const basic_json& val);

// (3)
iterator insert(const_iterator pos, const_iterator first, const_iterator last);

// (4)
iterator insert(const_iterator pos, initializer_list_t ilist);

// (5)
void insert(const_iterator first, const_iterator last);
```

1. Inserts element `val` into an array before iterator `pos`.
1. Inserts `cnt` copies of `val` into an array before iterator `pos`.
1. Inserts elements from range `[first, last)` into an array before iterator `pos`.
1. Inserts elements from initializer list `ilist` into an array before iterator `pos`.
1. Inserts elements from range `[first, last)` into an object.

## Iterator invalidation

For all cases where an element is added to an **array**, a reallocation can happen, in which case all iterators (including the [`end()`](https://json.nlohmann.me/api/basic_json/end/index.md) iterator) and all references to the elements are invalidated. Otherwise, only the [`end()`](https://json.nlohmann.me/api/basic_json/end/index.md) iterator is invalidated. Also, any iterator or reference after the insertion point will point to the same index, which is now a different value.

For [`ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md), also adding an element to an **object** can yield a reallocation which again invalidates all iterators and all references. Also, any iterator or reference after the insertion point will point to the same index, which is now a different value.

## Parameters

`pos` (in) : iterator before which the content will be inserted; may be the `end()` iterator

`val` (in) : value to insert

`cnt` (in) : number of copies of `val` to insert

`first` (in) : the start of the range of elements to insert

`last` (in) : the end of the range of elements to insert

`ilist` (in) : initializer list to insert the values from

## Return value

1. iterator pointing to the inserted `val`.
1. iterator pointing to the first element inserted, or `pos` if `cnt==0`
1. iterator pointing to the first element inserted, or `pos` if `first==last`
1. iterator pointing to the first element inserted, or `pos` if `ilist` is empty
1. (none)

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Exceptions

1. The function can throw the following exceptions:
   - Throws [`type_error.309`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error309) if called on JSON values other than arrays; example: `"cannot use insert() with string"`
   - Throws [`invalid_iterator.202`](https://json.nlohmann.me/home/exceptions/#jsonexceptioninvalid_iterator202) if called on an iterator which does not belong to the current JSON value; example: `"iterator does not fit current value"`
1. The function can throw the following exceptions:
   - Throws [`type_error.309`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error309) if called on JSON values other than arrays; example: `"cannot use insert() with string"`
   - Throws [`invalid_iterator.202`](https://json.nlohmann.me/home/exceptions/#jsonexceptioninvalid_iterator202) if called on an iterator which does not belong to the current JSON value; example: `"iterator does not fit current value"`
1. The function can throw the following exceptions:
   - Throws [`type_error.309`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error309) if called on JSON values other than arrays; example: `"cannot use insert() with string"`
   - Throws [`invalid_iterator.202`](https://json.nlohmann.me/home/exceptions/#jsonexceptioninvalid_iterator202) if called on an iterator which does not belong to the current JSON value; example: `"iterator does not fit current value"`
   - Throws [`invalid_iterator.210`](https://json.nlohmann.me/home/exceptions/#jsonexceptioninvalid_iterator210) if `first` and `last` do not belong to the same JSON value; example: `"iterators do not fit"`
   - Throws [`invalid_iterator.211`](https://json.nlohmann.me/home/exceptions/#jsonexceptioninvalid_iterator211) if `first` or `last` are iterators into container for which insert is called; example: `"passed iterators may not belong to container"`
1. The function can throw the following exceptions:
   - Throws [`type_error.309`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error309) if called on JSON values other than arrays; example: `"cannot use insert() with string"`
   - Throws [`invalid_iterator.202`](https://json.nlohmann.me/home/exceptions/#jsonexceptioninvalid_iterator202) if called on an iterator which does not belong to the current JSON value; example: `"iterator does not fit current value"`
1. The function can throw the following exceptions:
   - Throws [`type_error.309`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error309) if called on JSON values other than objects; example: `"cannot use insert() with string"`
   - Throws [`invalid_iterator.202`](https://json.nlohmann.me/home/exceptions/#jsonexceptioninvalid_iterator202) if `first` or `last` do not point to an object; example: `"iterators first and last must point to objects"`
   - Throws [`invalid_iterator.210`](https://json.nlohmann.me/home/exceptions/#jsonexceptioninvalid_iterator210) if `first` and `last` do not belong to the same JSON value; example: `"iterators do not fit"`

## Complexity

1. Constant plus linear in the distance between `pos` and end of the container.
1. Linear in `cnt` plus linear in the distance between `pos` and end of the container.
1. Linear in `std::distance(first, last)` plus linear in the distance between `pos` and end of the container.
1. Linear in `ilist.size()` plus linear in the distance between `pos` and end of the container.
1. Logarithmic: `O(N*log(size() + N))`, where `N` is the number of elements to insert.

## Examples

Example (1): insert element into array

The example shows how `insert()` is used.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON array
    json v = {1, 2, 3, 4};

    // insert number 10 before number 3
    auto new_pos = v.insert(v.begin() + 2, 10);

    // output new array and result of insert call
    std::cout << *new_pos << '\n';
    std::cout << v << '\n';
}
```

Output:

```
10
[1,2,10,3,4]
```

Example (2): insert copies of element into array

The example shows how `insert()` is used.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON array
    json v = {1, 2, 3, 4};

    // insert number 7 copies of number 7 before number 3
    auto new_pos = v.insert(v.begin() + 2, 7, 7);

    // output new array and result of insert call
    std::cout << *new_pos << '\n';
    std::cout << v << '\n';
}
```

Output:

```
7
[1,2,7,7,7,7,7,7,7,3,4]
```

Example (3): insert a range of elements into an array

The example shows how `insert()` is used.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON array
    json v = {1, 2, 3, 4};

    // create a JSON array to copy values from
    json v2 = {"one", "two", "three", "four"};

    // insert range from v2 before the end of array v
    auto new_pos = v.insert(v.end(), v2.begin(), v2.end());

    // output new array and result of insert call
    std::cout << *new_pos << '\n';
    std::cout << v << '\n';
}
```

Output:

```
"one"
[1,2,3,4,"one","two","three","four"]
```

Example (4): insert elements from an initializer list into an array

The example shows how `insert()` is used.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON array
    json v = {1, 2, 3, 4};

    // insert range from v2 before the end of array v
    auto new_pos = v.insert(v.end(), {7, 8, 9});

    // output new array and result of insert call
    std::cout << *new_pos << '\n';
    std::cout << v << '\n';
}
```

Output:

```
7
[1,2,3,4,7,8,9]
```

Example (5): insert a range of elements into an object

The example shows how `insert()` is used.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create two JSON objects
    json j1 = {{"one", "eins"}, {"two", "zwei"}};
    json j2 = {{"eleven", "elf"}, {"seventeen", "siebzehn"}};

    // output objects
    std::cout << j1 << '\n';
    std::cout << j2 << '\n';

    // insert range from j2 to j1
    j1.insert(j2.begin(), j2.end());

    // output result of insert call
    std::cout << j1 << '\n';
}
```

Output:

```
{"one":"eins","two":"zwei"}
{"eleven":"elf","seventeen":"siebzehn"}
{"eleven":"elf","one":"eins","seventeen":"siebzehn","two":"zwei"}
```

## See also

- [emplace](https://json.nlohmann.me/api/basic_json/emplace/index.md) add a value to an object
- [emplace_back](https://json.nlohmann.me/api/basic_json/emplace_back/index.md) add a value to an array
- [push_back](https://json.nlohmann.me/api/basic_json/push_back/index.md) add a value to an array/object
- [update](https://json.nlohmann.me/api/basic_json/update/index.md) merges objects

## Version history

1. Added in version 1.0.0.
1. Added in version 1.0.0.
1. Added in version 1.0.0.
1. Added in version 1.0.0.
1. Added in version 3.0.0.
