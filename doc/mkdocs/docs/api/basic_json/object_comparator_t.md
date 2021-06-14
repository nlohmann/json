# basic_json::object_comparator_t

```cpp
// until C++14
using object_comparator_t = std::less<StringType>;

// since C++14
using object_comparator_t = std::less<>;
```

The comparator used in [`object_t`](object_t.md).

When C++14 is detected, a transparent com parator is used which, when combined with perfect forwarding on find() and
count() calls, prevents unnecessary string construction.

## Version history

- Unknown.
