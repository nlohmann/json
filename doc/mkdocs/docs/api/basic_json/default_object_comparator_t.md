# <small>nlohmann::basic_json::</small>default_object_comparator_t

```cpp
using default_object_comparator_t = std::less<StringType>;  // until C++14

using default_object_comparator_t = std::less<>;            // since C++14
```

The default comparator used by [`object_t`](object_t.md).

Since C++14 a transparent comparator is used which prevents unnecessary string construction
when looking up a key in an object.

The actual comparator used depends on [`object_t`](object_t.md) and can be obtained via
[`object_comparator_t`](object_comparator_t.md).

## Version history

- Added in version 3.11.0.
