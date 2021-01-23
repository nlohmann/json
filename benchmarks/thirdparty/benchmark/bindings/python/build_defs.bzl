_SHARED_LIB_SUFFIX = {
    "//conditions:default": ".so",
    "//:windows": ".dll",
}

def py_extension(name, srcs, hdrs = [], copts = [], features = [], deps = []):
    for shared_lib_suffix in _SHARED_LIB_SUFFIX.values():
        shared_lib_name = name + shared_lib_suffix
        native.cc_binary(
            name = shared_lib_name,
            linkshared = 1,
            linkstatic = 1,
            srcs = srcs + hdrs,
            copts = copts,
            features = features,
            deps = deps,
        )

    return native.py_library(
        name = name,
        data = select({
            platform: [name + shared_lib_suffix]
            for platform, shared_lib_suffix in _SHARED_LIB_SUFFIX.items()
        }),
    )
