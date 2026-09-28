# Header only

[`json.hpp`](https://github.com/nlohmann/json/blob/develop/single_include/nlohmann/json.hpp) is the single required
file in `single_include/nlohmann` or [released here](https://github.com/nlohmann/json/releases). You need to add

```cpp
#include <nlohmann/json.hpp>

// for convenience
using json = nlohmann::json;
```

to the files you want to process JSON and set the necessary switches to enable C++11 (e.g., `-std=c++11` for GCC and
Clang).

You can further use file
[`single_include/nlohmann/json_fwd.hpp`](https://github.com/nlohmann/json/blob/develop/single_include/nlohmann/json_fwd.hpp)
for forward declarations, and file
[`single_include/nlohmann/json_literals.hpp`](https://github.com/nlohmann/json/blob/develop/single_include/nlohmann/json_literals.hpp)
for the user-defined string literals if you define
[`JSON_NO_AUTOMATIC_UDLS`](../api/macros/json_no_automatic_udls.md).

For the read-only, non-owning [`basic_json_document`](../api/basic_json_document/index.md)/[`basic_json_view`](../api/basic_json_view/index.md)
types, additionally include
[`single_include/nlohmann/json_view.hpp`](https://github.com/nlohmann/json/blob/develop/single_include/nlohmann/json_view.hpp);
see [Zero-copy JSON views](../features/json_view.md).
