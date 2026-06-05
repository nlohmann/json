# test linking library built with different JSON_DIAGNOSTICS setting
# into the same executable

# compile code using JSON_DIAGNOSTICS=1
add_library(abi_compat_diag_on STATIC diag_on.cpp)
target_link_libraries(abi_compat_diag_on PUBLIC abi_compat_common)

# compile code using JSON_DIAGNOSTICS=0
add_library(abi_compat_diag_off STATIC diag_off.cpp)
target_link_libraries(abi_compat_diag_off PUBLIC abi_compat_common)

# build test executable and add test
add_executable(abi_compat_diag diag.cpp)
target_link_libraries(abi_compat_diag PRIVATE
    abi_compat_main abi_compat_diag_on abi_compat_diag_off)

add_test(
    NAME test-abi_compat_diag
    COMMAND abi_compat_diag ${DOCTEST_TEST_FILTER})
