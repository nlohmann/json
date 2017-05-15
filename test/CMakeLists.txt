add_library(catch_main OBJECT
    "src/unit.cpp"
)
set_target_properties(catch_main PROPERTIES
    CXX_STANDARD 11
    CXX_STANDARD_REQUIRED ON
)
target_include_directories(catch_main PRIVATE "thirdparty/catch")

# The unit test executable.
set(JSON_UNITTEST_TARGET_NAME "json_unit")
add_executable(${JSON_UNITTEST_TARGET_NAME}
    $<TARGET_OBJECTS:catch_main>
    "src/unit-algorithms.cpp"
    "src/unit-allocator.cpp"
    "src/unit-capacity.cpp"
    "src/unit-cbor.cpp"
    "src/unit-class_const_iterator.cpp"
    "src/unit-class_iterator.cpp"
    "src/unit-class_lexer.cpp"
    "src/unit-class_parser.cpp"
    "src/unit-comparison.cpp"
    "src/unit-concepts.cpp"
    "src/unit-constructor1.cpp"
    "src/unit-constructor2.cpp"
    "src/unit-convenience.cpp"
    "src/unit-conversions.cpp"
    "src/unit-deserialization.cpp"
    "src/unit-element_access1.cpp"
    "src/unit-element_access2.cpp"
    "src/unit-inspection.cpp"
    "src/unit-iterator_wrapper.cpp"
    "src/unit-iterators1.cpp"
    "src/unit-iterators2.cpp"
    "src/unit-json_patch.cpp"
    "src/unit-json_pointer.cpp"
    "src/unit-meta.cpp"
    "src/unit-modifiers.cpp"
    "src/unit-msgpack.cpp"
    "src/unit-noexcept.cpp"
    "src/unit-pointer_access.cpp"
    "src/unit-readme.cpp"
    "src/unit-reference_access.cpp"
    "src/unit-regression.cpp"
    "src/unit-serialization.cpp"
    "src/unit-testsuites.cpp"
    "src/unit-udt.cpp"
    "src/unit-unicode.cpp"
)

set_target_properties(${JSON_UNITTEST_TARGET_NAME} PROPERTIES
    CXX_STANDARD 11
    CXX_STANDARD_REQUIRED ON
)

if(MSVC)
    set_target_properties(${JSON_UNITTEST_TARGET_NAME} PROPERTIES
        COMPILE_DEFINITIONS "_SCL_SECURE_NO_WARNINGS"
        COMPILE_OPTIONS "/EHsc;$<$<CONFIG:Release>:/Od>"
    )
endif()

target_include_directories(${JSON_UNITTEST_TARGET_NAME} PRIVATE "src" "thirdparty/catch")
target_link_libraries(${JSON_UNITTEST_TARGET_NAME} ${JSON_TARGET_NAME})

include(cotire OPTIONAL)

if(COMMAND cotire)
    set_target_properties(${JSON_UNITTEST_TARGET_NAME} PROPERTIES
        COTIRE_ADD_UNITY_BUILD FALSE
        COTIRE_CXX_PREFIX_HEADER_INIT "src/prefix.hpp"
    )
    # HACK - CMAKE_INCLUDE_SYSTEM_FLAG_CXX has a trailing space, which Cotire doesn't strip
    # Technically, this fix should go in cotire.cmake. TODO - submit a pull request upstream.
    if (CMAKE_INCLUDE_SYSTEM_FLAG_CXX)
		string (STRIP "${CMAKE_INCLUDE_SYSTEM_FLAG_CXX}" CMAKE_INCLUDE_SYSTEM_FLAG_CXX)
    endif()
    cotire(${JSON_UNITTEST_TARGET_NAME})
endif()

add_test(NAME "${JSON_UNITTEST_TARGET_NAME}_default"
	COMMAND ${JSON_UNITTEST_TARGET_NAME}
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
add_test(NAME "${JSON_UNITTEST_TARGET_NAME}_all"
	COMMAND ${JSON_UNITTEST_TARGET_NAME} "*"
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
