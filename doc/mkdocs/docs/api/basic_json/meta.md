# basic_json::meta

```cpp
static basic_json meta();
```

This function returns a JSON object with information about the library, including the version number and information on
the platform and compiler.
    
## Return value

JSON object holding version information

key         | description
----------- | ---------------
`compiler`  | Information on the used compiler. It is an object with the following keys: `c++` (the used C++ standard), `family` (the compiler family; possible values are `clang`, `icc`, `gcc`, `ilecpp`, `msvc`, `pgcpp`, `sunpro`, and `unknown`), and `version` (the compiler version).
`copyright` | The copyright line for the library as string.
`name`      | The name of the library as string.
`platform`  | The used platform as string. Possible values are `win32`, `linux`, `apple`, `unix`, and `unknown`.
`url`       | The URL of the project as string.
`version`   | The version of the library. It is an object with the following keys: `major`, `minor`, and `patch` as defined by [Semantic Versioning](http://semver.org), and `string` (the version string).

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes to any JSON value.

## Complexity

Constant.

## Example

The following code shows an example output of the `meta()`
function.

```cpp
--8<-- "examples/meta.cpp"
```

Output:

```json
--8<-- "examples/meta.output"
```

## Version history

- Added in version 2.1.0.
