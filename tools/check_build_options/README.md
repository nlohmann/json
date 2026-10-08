# check_build_options

Checks that the Meson build and the pkg-config files offer the same options as the CMake target, so that a new CMake
option is not forgotten in one of them.

The compile definitions of the CMake target (`target_compile_definitions` in [`CMakeLists.txt`](../../CMakeLists.txt))
are the reference. When you add an option there, also add it to

- the pkg-config block in `CMakeLists.txt` (`NLOHMANN_JSON_PKGCONFIG_CFLAGS`),
- [`meson_options.txt`](../../meson_options.txt), named without the `JSON_` prefix and with the same default,
- [`meson.build`](../../meson.build) (`json_defines`), and
- the list of Meson options in
  [`docs/mkdocs/docs/integration/package_managers.md`](../../docs/mkdocs/docs/integration/package_managers.md).

Run the check with

```shell
make check_build_options
```

It needs only Python 3 and runs in the `ci_meson_install` CI job.
