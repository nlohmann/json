cmake_minimum_required(VERSION 3.30)

if(CMAKE_VERSION VERSION_LESS_EQUAL "3.31.7")
    set(CMAKE_EXPERIMENTAL_CXX_IMPORT_STD "0e5b6991-d74f-4b3d-a41c-cf096e0b2508")
elseif(CMAKE_VERSION VERSION_LESS_EQUAL "4.2.3")
    set(CMAKE_EXPERIMENTAL_CXX_IMPORT_STD "d0edc3af-4c50-42ea-a356-e2862fe7a444")
elseif(CMAKE_VERSION VERSION_LESS_EQUAL "4.3.4")
    set(CMAKE_EXPERIMENTAL_CXX_IMPORT_STD "451f2fe2-a8a2-47c3-bc32-94786d8fc91b")
elseif(CMAKE_VERSION VERSION_LESS_EQUAL "4.4.5")
    set(CMAKE_EXPERIMENTAL_CXX_IMPORT_STD "f35a9ac6-8463-4d38-8eec-5d6008153e7d")
endif()

project(json_test CXX)

include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-freflection" NLOHMANN_JSON_HAS_FREFLECTION)

if(NLOHMANN_JSON_HAS_FREFLECTION)
    set(CMAKE_CXX_STANDARD 26)
    set(NLOHMANN_JSON_MODULES_CPP26 ON)
else()
    # import std; requires C++23 and the std library module
    set(CMAKE_CXX_STANDARD 23)
    set(NLOHMANN_JSON_MODULES_CPP26 OFF)
endif()

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_MODULE_STD ON)

set(NLOHMANN_JSON_BUILD_MODULES ON CACHE BOOL "Enable nlohmann.json module support")

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../.. ${CMAKE_CURRENT_BINARY_DIR}/tests)

add_executable(json_test basic.cpp)
target_link_libraries(json_test
    PRIVATE
        nlohmann_json_modules
)

if(NLOHMANN_JSON_MODULES_CPP26)
    add_executable(json_test_cpp26 reflection.cpp)
    target_link_libraries(json_test_cpp26
        PRIVATE
            nlohmann_json_modules
    )
    target_compile_features(json_test_cpp26 PRIVATE cxx_std_26)
endif()
