# Clang-Tidy

The library comes with a [clang-tidy](https://clang.llvm.org/extra/clang-tidy/) plugin.
It is disabled by default but can be enabled by enabling the `JSON_ClangTidyPlugin` [CMake option](cmake.md#json_clangtidyplugin).
Clang-tidy [Plugins](https://clang.llvm.org/extra/clang-tidy/ExternalClang-TidyExamples.html) are only supported by Clang 16 and later.
It is currently tested with Clang versions 16 to 22.
The plugin is not covered by the nlohmann-json's ABI stability guarantees and its behaviour may change.

## Building the plugin

You will need to have the development files matching your version of clang-tidy installed to build the plugin.
For example, if you are running on a Debian-derived Linux distribution:

```sh
apt install clang-tidy libclang-dev
```
but if this installs a version that is older than Clang 16 then you might be able to specify a newer version. For example:
```sh
apt install clang-tidy-19 libclang-19-dev
```

```sh
mkdir build
cd build
cmake -DJSON_ClangTidyPlugin=ON ..
cmake --build .
```

# Running the plugin
To tell clang-tidy to use the plugin you must pass a path to it as an argument to the `-load` option.
For example, you can run clang-tidy with only the _modernize-nlohmann-json-explicit-conversion_ check using the plugin on a single file with:
```sh
clang-tidy -load .../path/to/build/clang_tidy_plugin/libNlohmannJsonClangTidyPlugin.so -checks='-*,modernize-nlohmann-json-explicit-conversions` -fix source.cpp
clang-tidy
```
or you can create a `.clang-tidy` file to enable the checks you require.

# Checks

At the moment the plugin contains only a single check.

## modernize-nlohmann-json-explicit-conversions

This check converts code that takes advantage of [implicit conversions](../api/macros/json_use_implicit_conversions.md) to use explicit `get()` calls using the correct templated type.
For example, it turns:
```c++
void f(const nlohmann::json &j1, const nlohmann::json &j2, const nlohmann::json *pj)
{
  int i = j1.at("value1");
  double d = j1["value2"];
  bool b1 = *j1.find("valid");
  bool b2 = j2;
  const auto s = static_cast<std::string>(*pj);
  const auto m = MyStruct{j2};
  std::cout << i << " " << d << " " << b1 << " " << b2 << " " << s << " " << m << "\n";
}
```
into
```c++
void f(const nlohmann::json &j1, const nlohmann::json &j2, const nlohmann::json *pj)
{
  int i = j1.at("value1").get<int>();
  double d = j1["value2").get<double>();
  bool b1 = j1.find("valid")->get<bool>();
  bool b2 = j.find("valid")->get<bool>();
  const auto s = pj->get<std::string>();
  const auto m = j2.get<MyStruct>();
  std::cout << i << " " << d << " " << b1 << " " << b2 << " " << s << " " << m << "\n";
}
```
by knowing what the target type is for the implicit conversion and turning
that into an explicit call to the `get()` method with that type as the
template parameter and removing any now-unnecessary cast.

Unfortunately the check does not work very well if the implicit conversion
occurs in templated code or in a system header. For example, the following
won't be fixed because the implicit conversion will happen inside
`std::optional`'s constructor:
```c++
void f(const nlohmann::json &j)
{
  std::optional<int> oi;
  const auto &it = j.find("value");
  if (it != j.end())
    oi = *it;
  // ...
}
```
After you have run this check you can set [JSON_USE_IMPLICIT_CONVERSIONS=0](../api/macros/json_use_implicit_conversions.md) to find any occurrences that the check have not been fixed automatically.

### Limitations

#### Typedefs may leak platform specifics

The check sees through `typedef` which can cause types that ought to vary by platform to become fixed by the check. This is particularly a problem when using the fixed-sized types from `<cstdint>` or other platform-specific types like `size_t` and `off_t`. For example, converting:
```c++
uint64_t u64 = j.at("value");
```
in a 64-bit Linux environment will result in:
```c++
uint64_t u64 = j.at("value").get<unsigned long>();
```
but in a 32-bit Linux environment will result in:
```c++
uint64_t u64 = j.at("value").get<unsigned long long>();
```

This could cause serious bugs. If you use such types in code you apply the check to it is recommended that you run on all your target platforms and compare the results.

Other more-benign uses of `typedef` types may also cause the resultant code to look uglier. The check automatically turns `std::basic_string<char>` back into `std::string` since that is so common.

#### Fixes in template definitions and instantiations

If the implicit conversion is not dependent on a template parameter then it will be fixed in the definition since the type is known.

If the implicit conversion is dependent on a template parameter then the type is not known so it will not be fixed. A warning will be emitted to allow the code to be fixed by hand.

#### Redundant casts

Code using the library may use casts to force the correct type. These casts will be removed. For example, converting:
```c++
const auto value1 = static_cast<int>(j1["value"]);
const auto value2 = (double)*pj;
const auto value3 = std::string{*pj3};
const auto value4 = std::string(j4["value"]);
```
will yield:
```
const auto value1 = j1["value"].get<int>();
const auto value2 = pj->get<double>();
const auto value3 = pj2->get<std::string>();
const auto value4 = j4["value"]->get<std::string>();
```
