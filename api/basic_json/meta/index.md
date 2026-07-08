# nlohmann::basic_json::meta

```
static basic_json meta();
```

This function returns a JSON object with information about the library, including the version number and information on the platform and compiler.

## Return value

JSON object holding version information

| key         | description                                                                                                                                                                                                                                                                                                                                      |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `compiler`  | Information on the used compiler. It is an object with the following keys: `c++` (the used C++ standard), `family` (the compiler family; possible values are `clang`, `icc`, `gcc`, `ilecpp`, `msvc`, `pgcpp`, `sunpro`, and `unknown`), and `version` (the compiler version). On HP aCC compilers, `compiler` is instead the plain string `hp`. |
| `copyright` | The copyright line for the library as string.                                                                                                                                                                                                                                                                                                    |
| `name`      | The name of the library as string.                                                                                                                                                                                                                                                                                                               |
| `platform`  | The used platform as string. Possible values are `win32`, `linux`, `apple`, `unix`, and `unknown`.                                                                                                                                                                                                                                               |
| `url`       | The URL of the project as string.                                                                                                                                                                                                                                                                                                                |
| `version`   | The version of the library. It is an object with the following keys: `major`, `minor`, and `patch` as defined by [Semantic Versioning](http://semver.org), and `string` (the version string).                                                                                                                                                    |

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes to any JSON value.

## Complexity

Constant.

## Examples

Example

The following code shows an example output of the `meta()` function.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // call meta()
    std::cout << std::setw(4) << json::meta() << '\n';
}
```

Output:

```
{
    "compiler": {
        "c++": "201103",
        "family": "gcc",
        "version": "12.4.0"
    },
    "copyright": "(C) 2013-2026 Niels Lohmann",
    "name": "JSON for Modern C++",
    "platform": "apple",
    "url": "https://github.com/nlohmann/json",
    "version": {
        "major": 3,
        "minor": 12,
        "patch": 0,
        "string": "3.12.0"
    }
}
```

Note the output is platform-dependent.

## See also

- [**NLOHMANN_JSON_VERSION_MAJOR**/**NLOHMANN_JSON_VERSION_MINOR**/**NLOHMANN_JSON_VERSION_PATCH**](https://json.nlohmann.me/api/macros/nlohmann_json_version_major/index.md)
  - library version information

## Version history

- Added in version 2.1.0.
