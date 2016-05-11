# The unit test executable.
add_executable(json_unit
    "src/catch.hpp"
    "src/unit.cpp"
)

set_target_properties(json_unit PROPERTIES
    CXX_STANDARD 11
    CXX_STANDARD_REQUIRED ON
    COMPILE_DEFINITIONS "$<$<CXX_COMPILER_ID:MSVC>:_SCL_SECURE_NO_WARNINGS>"
    COMPILE_OPTIONS "$<$<CXX_COMPILER_ID:MSVC>:/EHsc;$<$<CONFIG:Release>:/Od>>"
)

# Install the test binary.
install(TARGETS json_unit RUNTIME DESTINATION test/bin)

# Copy the test data to the install tree.
install(DIRECTORY data/ DESTINATION test/data)

target_include_directories(json_unit PRIVATE "src")
target_link_libraries(json_unit ${JSON_TARGET_NAME})
