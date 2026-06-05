# test the different options to change the namespace

# test default namespace
add_executable(abi_config_default default.cpp)
target_link_libraries(abi_config_default PRIVATE abi_compat_main)
add_test(
    NAME test-abi_config_default
    COMMAND abi_config_default ${DOCTEST_TEST_FILTER})

# test no version namespace
add_executable(abi_config_noversion noversion.cpp)
target_link_libraries(abi_config_noversion PRIVATE abi_compat_main)
add_test(
    NAME test-abi_config_noversion
    COMMAND abi_config_noversion ${DOCTEST_TEST_FILTER})

# test custom namespace
add_executable(abi_config_custom custom.cpp)
target_link_libraries(abi_config_custom PRIVATE abi_compat_main)
add_test(
    NAME test-abi_config_custom
    COMMAND abi_config_custom ${DOCTEST_TEST_FILTER})
