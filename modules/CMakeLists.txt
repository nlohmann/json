file(GLOB_RECURSE NLOHMANN_JSON_MODULES json.cppm)

add_library(nlohmann_json_modules)

cmake_minimum_required(VERSION 3.28)

if(NOT COMMAND configure_cpp_module_target)
    function(configure_cpp_module_target target)
        if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.28)
            target_sources(${target} PUBLIC FILE_SET CXX_MODULES FILES ${NLOHMANN_JSON_MODULES})
        else()
            message(WARNING "C++ modules require CMake 3.28+. Using standard compilation.")
            target_sources(${target} PRIVATE ${NLOHMANN_JSON_MODULES})
        endif()
    endfunction()
endif()

configure_cpp_module_target(nlohmann_json_modules)

target_link_libraries(nlohmann_json_modules
    PUBLIC
    nlohmann_json::nlohmann_json
)

target_include_directories(nlohmann_json_modules
    PRIVATE
    ${PROJECT_SOURCE_DIR}/include
)

target_compile_features(nlohmann_json_modules PUBLIC cxx_std_20)
