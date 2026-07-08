# nlohmann::basic_json::update

```
// (1)
void update(const_reference j, bool merge_objects = false);

// (2)
void update(const_iterator first, const_iterator last, bool merge_objects = false);
```

1. Inserts all values from JSON object `j`.
1. Inserts all values from range `[first, last)`

When `merge_objects` is `false` (default), existing keys are overwritten. When `merge_objects` is `true`, recursively merges objects with common keys.

If the JSON value is `null`, it is implicitly converted to an empty object before the values are inserted.

The function is motivated by Python's [dict.update](https://docs.python.org/3.6/library/stdtypes.html#dict.update) function.

## Iterator invalidation

For [`ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md), adding a value to an object can yield a reallocation, in which case all iterators (including the `end()` iterator) and all references to the elements are invalidated.

## Parameters

`j` (in) : JSON object to read values from

`merge_objects` (in) : when `true`, keys that exist in both objects and whose value in the source is itself an object are merged recursively; all other values are overwritten as usual (default: `false`)

`first` (in) : the beginning of the range of elements to insert

`last` (in) : the end of the range of elements to insert

## Exception safety

Basic guarantee: if an exception is thrown during the operation, the JSON value may be partially modified.

## Exceptions

1. The function can throw the following exceptions:
   - Throws [`type_error.312`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error312) if called on JSON values other than objects; example: `"cannot use update() with string"`
1. The function can throw the following exceptions:
   - Throws [`type_error.312`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error312) if called on JSON values other than objects; example: `"cannot use update() with string"`
   - Throws [`invalid_iterator.210`](https://json.nlohmann.me/home/exceptions/#jsonexceptioninvalid_iterator210) if `first` and `last` do not belong to the same JSON value; example: `"iterators do not fit"`

## Complexity

1. O(N\*log(size() + N)), where N is the number of elements to insert.
1. O(N\*log(size() + N)), where N is the number of elements to insert.

## Examples

Example

The example shows how `update()` is used.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace nlohmann::literals;

int main()
{
    // create two JSON objects
    json o1 = R"( {"color": "red", "price": 17.99, "names": {"de": "Flugzeug"}} )"_json;
    json o2 = R"( {"color": "blue", "speed": 100, "names": {"en": "plane"}} )"_json;
    json o3 = o1;

    // add all keys from o2 to o1 (updating "color", replacing "names")
    o1.update(o2);

    // add all keys from o2 to o1 (updating "color", merging "names")
    o3.update(o2, true);

    // output updated object o1 and o3
    std::cout << std::setw(2) << o1 << '\n';
    std::cout << std::setw(2) << o3 << '\n';
}
```

Output:

```
{
  "color": "blue",
  "names": {
    "en": "plane"
  },
  "price": 17.99,
  "speed": 100
}
{
  "color": "blue",
  "names": {
    "de": "Flugzeug",
    "en": "plane"
  },
  "price": 17.99,
  "speed": 100
}
```

Example

The example shows how `update()` is used.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace nlohmann::literals;

int main()
{
    // create two JSON objects
    json o1 = R"( {"color": "red", "price": 17.99, "names": {"de": "Flugzeug"}} )"_json;
    json o2 = R"( {"color": "blue", "speed": 100, "names": {"en": "plane"}} )"_json;
    json o3 = o1;

    // add all keys from o2 to o1 (updating "color", replacing "names")
    o1.update(o2.begin(), o2.end());

    // add all keys from o2 to o1 (updating "color", merging "names")
    o3.update(o2.begin(), o2.end(), true);

    // output updated object o1 and o3
    std::cout << std::setw(2) << o1 << '\n';
    std::cout << std::setw(2) << o3 << '\n';
}
```

Output:

```
{
  "color": "blue",
  "names": {
    "en": "plane"
  },
  "price": 17.99,
  "speed": 100
}
{
  "color": "blue",
  "names": {
    "de": "Flugzeug",
    "en": "plane"
  },
  "price": 17.99,
  "speed": 100
}
```

Example

One common use case for this function is the handling of user settings. Assume your application can be configured in some aspects:

```
{
    "color": "red",
    "active": true,
    "name": {"de": "Maus", "en": "mouse"}
}
```

The user may override the default settings selectively:

```
{
    "color": "blue",
    "name": {"es": "ratón"},
}
```

Then `update` manages the merging of default settings and user settings:

```
auto user_settings = json::parse("config.json");
auto effective_settings = get_default_settings();
effective_settings.update(user_settings);
```

Now `effective_settings` contains the default settings, but those keys set by the user are overwritten:

```
{
    "color": "blue",
    "active": true,
    "name": {"es": "ratón"}
}
```

Note existing keys were just overwritten. To merge objects, `merge_objects` setting should be set to `true`:

```
auto user_settings = json::parse("config.json");
auto effective_settings = get_default_settings();
effective_settings.update(user_settings, true);
```

```
{
    "color": "blue",
    "active": true,
    "name": {"de": "Maus", "en": "mouse", "es": "ratón"}
}
```

## See also

- [insert](https://json.nlohmann.me/api/basic_json/insert/index.md) add values to an array/object
- [merge_patch](https://json.nlohmann.me/api/basic_json/merge_patch/index.md) applies a JSON Merge Patch
- [Modifying values](https://json.nlohmann.me/features/modifying_values/index.md) - the article on modifying values

## Version history

- Added in version 3.0.0.
- Added `merge_objects` parameter in 3.10.5.
