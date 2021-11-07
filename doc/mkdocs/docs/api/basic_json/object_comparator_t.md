# <small>nlohmann::basic_json::</small>object_comparator_t

```cpp
using object_comparator_t = std::less<StringType>;  // until C++14

using object_comparator_t = std::less<>;            // since C++14
```

The comparator used in [`object_t`](object_t.md).

When C++14 is detected, a transparent com parator is used which, when combined with perfect forwarding on find() and
count() calls, prevents unnecessary string construction.

## Version history

- Unknown.
