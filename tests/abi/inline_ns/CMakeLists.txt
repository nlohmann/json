# test linking an old library version without an inline namespace
# with the current library using an inline namespace into the same executable

# build test executable and add test
add_executable(abi_compat_inline_ns
    use_v3_10_5.cpp
    use_current.cpp)
target_link_libraries(abi_compat_inline_ns PRIVATE abi_compat_main)

add_test(
    NAME test-abi_compat_inline_ns
    COMMAND abi_compat_inline_ns ${DOCTEST_TEST_FILTER})
