# <small>nlohmann::basic_json_document::</small>shrink_to_fit

```cpp
void shrink_to_fit();
```

Releases capacity that is no longer needed, both of the node index and of the buffer for decoded strings (strings that
contained escape sequences), e.g. after [`read()`](read.md) replaced a large document with a much smaller one. Like
`#!cpp std::vector::shrink_to_fit()`, this is a non-binding request: the library may keep more capacity than strictly
necessary.

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes to the document.

## Exceptions

May throw `#!cpp std::bad_alloc` if the reallocation fails; on exception, the document is unchanged.

## Complexity

Linear in [`node_count()`](node_count.md) plus the length of the decoded strings.

## Notes

!!! warning "Invalidates views"

    Unlike moving the document, `shrink_to_fit()` **invalidates every view taken from this document before the
    call**, including a previously obtained [`root()`](root.md): the node index is moved into a new, smaller
    allocation, and the old one is freed. Take a fresh view from [`root()`](root.md) after calling this function.

This is unlike `#!cpp std::vector::shrink_to_fit()`, which promises nothing about validity but in practice often
leaves iterators alone when it did not need to reallocate; here, an implementation that avoids a reallocation when
possible would be an internal optimization only, not a guarantee to rely on.

## Examples

??? example

    ```cpp
    #include <iostream>
    #include <sstream>
    #include <string>
    #include <nlohmann/json_view.hpp>
    
    using json_document = nlohmann::json_document;
    
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

    ```json
    true
    true
    true 1
    
    ```

## See also

- [node_count](node_count.md) - the number of index entries
- [memory_usage](memory_usage.md) - the number of bytes held by the document
- [root](root.md) - the view of the root value

## Version history

- Added in version 3.13.0.
