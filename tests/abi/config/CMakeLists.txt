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

# test default and no version namespace with all ABI tags enabled, so the
# expected tag order is checked regardless of the JSON_* CMake options
foreach(test default noversion)
    add_executable(abi_config_${test}_all_tags ${test}.cpp)
    target_compile_definitions(abi_config_${test}_all_tags PRIVATE
        JSON_DIAGNOSTICS=1
        JSON_DIAGNOSTIC_POSITIONS=1
        JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON=1)
    target_link_libraries(abi_config_${test}_all_tags PRIVATE abi_compat_main)
    add_test(
        NAME test-abi_config_${test}_all_tags
        COMMAND abi_config_${test}_all_tags ${DOCTEST_TEST_FILTER})
endforeach()

# test custom namespace
add_executable(abi_config_custom custom.cpp)
target_link_libraries(abi_config_custom PRIVATE abi_compat_main)
add_test(
    NAME test-abi_config_custom
    COMMAND abi_config_custom ${DOCTEST_TEST_FILTER})
