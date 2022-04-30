# <small>nlohmann::basic_json::</small>object_comparator_t


```cpp
using object_comparator_t = typename object_t::key_compare;
// or
using object_comparator_t = default_object_comparator_t;
```

The comparator used by [`object_t`](object_t.md). Defined as `#!cpp typename object_t::key_compare` if available,
and [`default_object_comparator_t`](default_object_comparator_t.md) otherwise.

## Version history

- Added in version 3.0.0.
- Changed to be conditionally defined as `#!cpp typename object_t::key_compare` or `default_object_comparator_t` in version 3.11.0.
