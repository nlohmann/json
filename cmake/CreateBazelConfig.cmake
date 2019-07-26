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
# Tommy Nguyen 07-26-2019 Remove functions we don't need.
# ~~~

# Generate a Bazel configuration file with the headers and sources for a given
# target. The generated file can be loaded from a BUILD file to create the
# corresponding targets in Bazel.
function (create_bazel_config TARGET)
    if (NOT TARGET ${TARGET})
        message(
            FATAL_ERROR "create_bazel_config requires a target name: ${TARGET}")
    endif ()
    set(filename "${TARGET}.bzl")
    set(H)
    set(CC)
    get_target_property(target_type ${TARGET} TYPE)
    get_target_property(sources ${TARGET} INTERFACE_SOURCES)
    foreach (src ${sources})
        if("${src}" MATCHES "\\.hpp$")
            list(APPEND H ${src})
        elseif("${src}" MATCHES "\\.cc$")
            list(APPEND CC ${src})
        endif ()
    endforeach ()
    file(APPEND "${filename}" [=[
"""Automatically generated source lists for ]=]
            )
    file(APPEND "${filename}" ${TARGET})
    file(APPEND "${filename}" [=[ - DO NOT EDIT."""

]=]
        )
    file(APPEND "${filename}" "${TARGET}_hdrs = [\n")
    foreach (src ${H})
        file(APPEND "${filename}" "    \"${src}\",\n")
    endforeach ()
    file(APPEND "${filename}" "]\n\n")
    file(APPEND "${filename}" "${TARGET}_srcs = [\n")
    foreach (src ${CC})
        file(APPEND "${filename}" "    \"${src}\",\n")
    endforeach ()
    file(APPEND "${filename}" "]\n")
endfunction ()
