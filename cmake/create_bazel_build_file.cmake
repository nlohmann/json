function (create_bazel_build_file NLOHMANN_JSON_INCLUDE_BUILD_DIR)
    message(STATUS "Generating Bazel BUILD file")
  
    file(GLOB_RECURSE NLOHMANN_JSON_HEADERS "${NLOHMANN_JSON_INCLUDE_BUILD_DIR}/*.hpp")
   
    set(filename "BUILD.bazel")
    file(WRITE "${filename}" "cc_library(\n")
    file(APPEND "${filename}" "    name = \"json\",\n")
    file(APPEND "${filename}" "    hdrs = glob([\n")

    foreach(_header ${NLOHMANN_JSON_HEADERS})
        file(RELATIVE_PATH _header_rel ${PROJECT_SOURCE_DIR} ${_header})
        file(APPEND "${filename}" "        \"${_header_rel}\",\n")
    endforeach()

    file(APPEND "${filename}" "    ]),\n")
    file(APPEND "${filename}" "    includes = [\"include\"],\n")
    file(APPEND "${filename}" "    visibility = [\"//visibility:public\"],\n")
    file(APPEND "${filename}" "    alwayslink = True,\n")
    file(APPEND "${filename}" ")\n")
endfunction ()
