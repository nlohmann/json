# Installed by Meson for find_package(nlohmann_json) compatibility with the CMake build.

if(NOT TARGET nlohmann_json::nlohmann_json)
    get_filename_component(
        _nlohmann_json_include_dir
        "${CMAKE_CURRENT_LIST_DIR}/../../../include"
        ABSOLUTE)
    add_library(nlohmann_json::nlohmann_json INTERFACE IMPORTED)
    set_target_properties(nlohmann_json::nlohmann_json PROPERTIES
        INTERFACE_COMPILE_FEATURES "cxx_std_11"
        INTERFACE_INCLUDE_DIRECTORIES "${_nlohmann_json_include_dir}"
    )
endif()
