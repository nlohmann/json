# nlohmann::basic_json_document::shrink_to_fit

```
void shrink_to_fit();
```

Releases capacity that is no longer needed, both of the node index and of the buffer for decoded strings (strings that contained escape sequences), e.g. after [`read()`](https://json.nlohmann.me/api/basic_json_document/read/index.md) replaced a large document with a much smaller one. Like `std::vector::shrink_to_fit()`, this is a non-binding request: the library may keep more capacity than strictly necessary.

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes to the document.

## Exceptions

May throw `std::bad_alloc` if the reallocation fails; on exception, the document is unchanged.

## Complexity

Linear in [`node_count()`](https://json.nlohmann.me/api/basic_json_document/node_count/index.md) plus the length of the decoded strings.

## Notes

The node index of a small document (an estimate of up to 1024 nodes, which is up to about 4 KiB of minified text) is allocated together with the document's header, so that parsing needs one allocation. That part cannot be released separately: `shrink_to_fit()` only trims a node index that has its own allocation, and the decoded strings.

Invalidates views

Unlike moving the document, `shrink_to_fit()` **invalidates every view taken from this document before the call**, including a previously obtained [`root()`](https://json.nlohmann.me/api/basic_json_document/root/index.md): the node index is moved into a new, smaller allocation, and the old one is freed. Take a fresh view from [`root()`](https://json.nlohmann.me/api/basic_json_document/root/index.md) after calling this function.

This is unlike `std::vector::shrink_to_fit()`, which promises nothing about validity but in practice often leaves iterators alone when it did not need to reallocate; here, an implementation that avoids a reallocation when possible would be an internal optimization only, not a guarantee to rely on.

## Examples

Example

```
#include <iostream>
#include <sstream>
#include <string>
#include <nlohmann/json_view.hpp>

using nlohmann::json_document;

int main()
{
    std::cout << std::boolalpha;

    // build a large array (many nodes), then read a small one into the same
    // document: the index grown for the large input is still allocated
    std::ostringstream big;
    big << '[';
    for (int i = 0; i < 500; ++i)
    {
        if (i != 0)
        {
            big << ',';
        }
        big << i;
    }
    big << ']';

    json_document doc;
    doc.read(big.str());
    const std::size_t big_nodes = doc.node_count();

    doc.read(std::string("[1]"));
    std::cout << (doc.node_count() < big_nodes) << '\n'; // far fewer live nodes now
    const std::size_t before = doc.memory_usage();

    // shrink_to_fit() moves the index into a block sized for what is actually
    // used. This INVALIDATES every view taken from this document before the
    // call (they point into the old, now-freed block) -- take fresh ones from
    // root() afterward.
    doc.shrink_to_fit();
    const std::size_t after = doc.memory_usage();
    std::cout << (after <= before) << '\n';

    // a freshly taken view is valid and correct
    std::cout << doc.root().is_array() << ' ' << doc.root().size() << '\n';
}
```

Output:

```
true
true
true 1
```

## See also

- [`node_count`](https://json.nlohmann.me/api/basic_json_document/node_count/index.md) - the number of index entries
- [`memory_usage`](https://json.nlohmann.me/api/basic_json_document/memory_usage/index.md) - the number of bytes held by the document
- [`root`](https://json.nlohmann.me/api/basic_json_document/root/index.md) - the view of the root value
- [Zero-copy JSON views](https://json.nlohmann.me/features/json_view/#ownership-and-lifetime) - what releasing memory invalidates

## Version history

- Added in version 3.13.0 unreleased.
