# ~~~
# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Tommy Nguyen 07-26-2019 Remove functions we don't need. Have the function
# take a list of sources rather than a target.
# ~~~

# Generate a Bazel configuration file with the headers and sources for a given
# list. The generated file can be loaded from a BUILD file to create the
# corresponding targets in Bazel.
function (create_bazel_config LIST)
    # No need to check for an empty list. CMake will complain for us.
    set(_LIST ${LIST} ${ARGN})
    set(filename "nlohmann_json.bzl")
    # Create a new file each time.
    file(WRITE "${filename}")
    set(H)
    set(CC)
    foreach (src ${_LIST})
        if("${src}" MATCHES "\\.hpp$")
            list(APPEND H ${src})
        elseif("${src}" MATCHES "\\.cpp$")
            list(APPEND CC ${src})
        endif ()
    endforeach ()
    file(APPEND "${filename}" [=[
"""Automatically generated source lists for ]=]
            )
    file(APPEND "${filename}" "nlohmann_json")
    file(APPEND "${filename}" [=[ - DO NOT EDIT."""

]=]
        )
    file(APPEND "${filename}" "nlohmann_json_hdrs = [\n")
    foreach (src ${H})
        file(APPEND "${filename}" "    \"${src}\",\n")
    endforeach ()
    file(APPEND "${filename}" "]\n\n")
    file(APPEND "${filename}" "nlohmann_json_srcs = [\n")
    foreach (src ${CC})
        file(APPEND "${filename}" "    \"${src}\",\n")
    endforeach ()
    file(APPEND "${filename}" "]\n")
endfunction ()
