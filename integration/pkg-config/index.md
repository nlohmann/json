# Pkg-config

If you are using bare Makefiles, you can use `pkg-config` to generate the include flags that point to where the library is installed:

```
pkg-config nlohmann_json --cflags
```

A pkg-config file is installed by [CMake](https://json.nlohmann.me/integration/cmake/#json_install) (when the `JSON_Install` option is enabled, which is the default for a top-level build) as well as by several [package managers](https://json.nlohmann.me/integration/package_managers/index.md).

Users of the [Meson build system](https://json.nlohmann.me/integration/package_managers/#meson) will also be able to use a system-wide library, which will be found by `pkg-config`:

```
json = dependency('nlohmann_json', required: true)
```
