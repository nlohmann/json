# Pkg-config

If you are using bare Makefiles, you can use `pkg-config` to generate the include flags that point to where the library is installed:

```sh
pkg-config nlohmann_json --cflags
```

Users of the [Meson build system](package_managers.md#meson) will also be able to use a system-wide library, which will be found by `pkg-config`:

```meson
json = dependency('nlohmann_json', required: true)
```
