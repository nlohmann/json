# common build settings
add_library(abi_compat_common INTERFACE)
target_compile_definitions(abi_compat_common INTERFACE
    DOCTEST_CONFIG_SUPER_FAST_ASSERTS
    JSON_TEST_KEEP_MACROS)
target_compile_features(abi_compat_common INTERFACE cxx_std_11)
target_compile_options(abi_compat_common INTERFACE
    $<$<CXX_COMPILER_ID:MSVC>:/EHsc;$<$<CONFIG:Release>:/Od>>
    # MSVC: Force to always compile with W4
    $<$<CXX_COMPILER_ID:MSVC>:/W4>

    # https://github.com/nlohmann/json/pull/3229
    $<$<CXX_COMPILER_ID:Intel>:-diag-disable=2196>

    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wno-deprecated;-Wno-float-equal>
    $<$<CXX_COMPILER_ID:GNU>:-Wno-deprecated-declarations>
    $<$<CXX_COMPILER_ID:Intel>:-diag-disable=1786>)
target_include_directories(abi_compat_common SYSTEM INTERFACE
    ../thirdparty/doctest
    include)
target_link_libraries(abi_compat_common INTERFACE ${NLOHMANN_JSON_TARGET_NAME})

# shared main()
add_library(abi_compat_main STATIC main.cpp)
target_link_libraries(abi_compat_main PUBLIC abi_compat_common)

# add individual tests
add_subdirectory(config)
add_subdirectory(diag)
add_subdirectory(inline_ns)
