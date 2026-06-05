# JSON_SKIP_LIBRARY_VERSION_CHECK

```cpp
#define JSON_SKIP_LIBRARY_VERSION_CHECK
```

When defined, the library will not create a compiler warning when a different version of the library was already
included.

## Default definition

By default, the macro is not defined.

```cpp
#undef JSON_SKIP_LIBRARY_VERSION_CHECK
```

## Notes

!!! danger "ABI compatibility"

    Mixing different library versions in the same code can be a problem as the different versions may not be ABI
    compatible.

## Examples

!!! example

    The following warning will be shown in case a different version of the library was already included:

    ```
    Already included a different version of the library!
    ```

## Version history

Added in version 3.11.0.
