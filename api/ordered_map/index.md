# nlohmann::ordered_map

```
template<class Key, class T, class IgnoredLess = std::less<Key>,
         class Allocator = std::allocator<std::pair<const Key, T>>>
struct ordered_map : std::vector<std::pair<const Key, T>, Allocator>;
```

A minimal map-like container that preserves insertion order for use within [`nlohmann::ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md) (`nlohmann::basic_json<ordered_map>`).

## Template parameters

`Key` : key type

`T` : mapped type

`IgnoredLess` : comparison function (ignored and only added to ensure compatibility with `std::map`)

`Allocator` : allocator type

## Iterator invalidation

The type uses a `std::vector` to store object elements. Therefore, adding elements can yield a reallocation in which case all iterators (including the `end()` iterator) and all references to the elements are invalidated.

## Member types

- **key_type** - key type (`Key`)

- **mapped_type** - mapped type (`T`)

- **Container** - base container type (`std::vector<std::pair<const Key, T>, Allocator>`)

- **iterator**

- **const_iterator**

- **size_type**

- **value_type**

- **key_compare** - key comparison function

  ```
  std::equal_to<Key>  // until C++14

  std::equal_to<>     // since C++14
  ```

## Member functions

- (constructor)
- (destructor)
- **emplace**
- **operator[]**
- **at**
- **erase**
- **count**
- **find**
- **insert**

## Complexity

Because the elements are stored in a `std::vector` in insertion order, there is no index to look a key up by. Every key-based operation performs a **linear scan** over the stored elements. With `n` denoting the number of elements in the container:

| Operation                              | Complexity     | Note                                                     |
| -------------------------------------- | -------------- | -------------------------------------------------------- |
| **emplace**                            | O(n)           | scans for an existing key, then appends (amortized O(1)) |
| **operator[]**                         | O(n)           | delegates to **emplace** (non-const) or **at** (const)   |
| **at**                                 | O(n)           | throws `std::out_of_range` if the key is not found       |
| **find**                               | O(n)           |                                                          |
| **count**                              | O(n)           | the result is always 0 or 1                              |
| **erase(key)**                         | O(n)           | scan, then move the remaining elements one position down |
| **erase(pos)**, **erase(first, last)** | O(n)           | moves all elements after the erased range                |
| **insert(value)**                      | O(n)           | equivalent to **emplace**                                |
| **insert(first, last)**                | O((n + m) * m) | for `m` inserted elements                                |

This differs from `std::map`, where the same operations are O(log n).

Quadratic cost of building large objects

Because every insertion scans all elements inserted so far, building an object of `n` distinct keys costs **O(n²)** in total. This applies to filling an [`ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md) object key by key as well as to parsing one, since the parser inserts each key as it is read.

The cost is negligible for the object sizes typically found in configuration files or API payloads, but it grows steeply for machine-generated objects with many thousands of keys. Measured with `-O2 -DNDEBUG` for parsing a flat object of `n` keys, relative to `nlohmann::json` (which uses `std::map`):

| `n`    | `json` | `ordered_json` | factor |
| ------ | ------ | -------------- | ------ |
| 2000   | 0.7 ms | 3.6 ms         | 5×     |
| 4000   | 0.8 ms | 14.0 ms        | 19×    |
| 8000   | 1.6 ms | 67.8 ms        | 43×    |
| 16 000 | 3.3 ms | 181.6 ms       | 54×    |

If key order matters for objects of that size, consider a container with a lookup index, such as [`tsl::ordered_map`](https://github.com/Tessil/ordered-map) ([integration](https://github.com/nlohmann/json/issues/546#issuecomment-304447518)), as the object type -- see [object order](https://json.nlohmann.me/features/object_order/index.md).

## Examples

Example

The example shows the different behavior of `std::map` and `nlohmann::ordered_map`.

```
#include <iostream>
#include <nlohmann/json.hpp>

// simple output function
template<typename Map>
void output(const char* prefix, const Map& m)
{
    std::cout << prefix << " = { ";
    for (auto& element : m)
    {
        std::cout << element.first << ":" << element.second << ' ';
    }
    std::cout << "}" << std::endl;
}

int main()
{
    // create and fill two maps
    nlohmann::ordered_map<std::string, std::string> m_ordered;
    m_ordered["one"] = "eins";
    m_ordered["two"] = "zwei";
    m_ordered["three"] = "drei";

    std::map<std::string, std::string> m_std;
    m_std["one"] = "eins";
    m_std["two"] = "zwei";
    m_std["three"] = "drei";

    // output: m_ordered is ordered by insertion order, m_std is ordered by key
    output("m_ordered", m_ordered);
    output("m_std", m_std);

    // erase and re-add "one" key
    m_ordered.erase("one");
    m_ordered["one"] = "eins";

    m_std.erase("one");
    m_std["one"] = "eins";

    // output: m_ordered shows newly added key at the end; m_std is again ordered by key
    output("m_ordered", m_ordered);
    output("m_std", m_std);
}
```

Output:

```
m_ordered = { one:eins two:zwei three:drei }
m_std = { one:eins three:drei two:zwei }
m_ordered = { two:zwei three:drei one:eins }
m_std = { one:eins three:drei two:zwei }
```

## See also

- [ordered_json](https://json.nlohmann.me/api/ordered_json/index.md)

## Version history

- Added in version 3.9.0 to implement [`nlohmann::ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md).
- Added **key_compare** member in version 3.11.0.
