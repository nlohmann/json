# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

#[=======================================================================[.rst:
Catch
-----

This module defines a function to help use the Catch test framework.

The :command:`catch_discover_tests` discovers tests by asking the compiled test
executable to enumerate its tests.  This does not require CMake to be re-run
when tests change.  However, it may not work in a cross-compiling environment,
and setting test properties is less convenient.

This command is intended to replace use of :command:`add_test` to register
tests, and will create a separate CTest test for each Catch test case.  Note
that this is in some cases less efficient, as common set-up and tear-down logic
cannot be shared by multiple test cases executing in the same instance.
However, it provides more fine-grained pass/fail information to CTest, which is
usually considered as more beneficial.  By default, the CTest test name is the
same as the Catch name; see also ``TEST_PREFIX`` and ``TEST_SUFFIX``.

.. command:: catch_discover_tests

  Automatically add tests with CTest by querying the compiled test executable
  for available tests::

    catch_discover_tests(target
                         [TEST_SPEC arg1...]
                         [EXTRA_ARGS arg1...]
                         [WORKING_DIRECTORY dir]
                         [TEST_PREFIX prefix]
                         [TEST_SUFFIX suffix]
                         [PROPERTIES name1 value1...]
                         [TEST_LIST var]
                         [REPORTER reporter]
                         [OUTPUT_DIR dir]
                         [OUTPUT_PREFIX prefix}
                         [OUTPUT_SUFFIX suffix]
    )

  ``catch_discover_tests`` sets up a post-build command on the test executable
  that generates the list of tests by parsing the output from running the test
  with the ``--list-test-names-only`` argument.  This ensures that the full
  list of tests is obtained.  Since test discovery occurs at build time, it is
  not necessary to re-run CMake when the list of tests changes.
  However, it requires that :prop_tgt:`CROSSCOMPILING_EMULATOR` is properly set
  in order to function in a cross-compiling environment.

  Additionally, setting properties on tests is somewhat less convenient, since
  the tests are not available at CMake time.  Additional test properties may be
  assigned to the set of tests as a whole using the ``PROPERTIES`` option.  If
  more fine-grained test control is needed, custom content may be provided
  through an external CTest script using the :prop_dir:`TEST_INCLUDE_FILES`
  directory property.  The set of discovered tests is made accessible to such a
  script via the ``<target>_TESTS`` variable.

  The options are:

  ``target``
    Specifies the Catch executable, which must be a known CMake executable
    target.  CMake will substitute the location of the built executable when
    running the test.

  ``TEST_SPEC arg1...``
    Specifies test cases, wildcarded test cases, tags and tag expressions to
    pass to the Catch executable with the ``--list-test-names-only`` argument.

  ``EXTRA_ARGS arg1...``
    Any extra arguments to pass on the command line to each test case.

  ``WORKING_DIRECTORY dir``
    Specifies the directory in which to run the discovered test cases.  If this
    option is not provided, the current binary directory is used.

  ``TEST_PREFIX prefix``
    Specifies a ``prefix`` to be prepended to the name of each discovered test
    case.  This can be useful when the same test executable is being used in
    multiple calls to ``catch_discover_tests()`` but with different
    ``TEST_SPEC`` or ``EXTRA_ARGS``.

  ``TEST_SUFFIX suffix``
    Similar to ``TEST_PREFIX`` except the ``suffix`` is appended to the name of
    every discovered test case.  Both ``TEST_PREFIX`` and ``TEST_SUFFIX`` may
    be specified.

  ``PROPERTIES name1 value1...``
    Specifies additional properties to be set on all tests discovered by this
    invocation of ``catch_discover_tests``.

  ``TEST_LIST var``
    Make the list of tests available in the variable ``var``, rather than the
    default ``<target>_TESTS``.  This can be useful when the same test
    executable is being used in multiple calls to ``catch_discover_tests()``.
    Note that this variable is only available in CTest.

  ``REPORTER reporter``
    Use the specified reporter when running the test case. The reporter will
    be passed to the Catch executable as ``--reporter reporter``.

  ``OUTPUT_DIR dir``
    If specified, the parameter is passed along as
    ``--out dir/<test_name>`` to Catch executable. The actual file name is the
    same as the test name. This should be used instead of
    ``EXTRA_ARGS --out foo`` to avoid race conditions writing the result output
    when using parallel test execution.

  ``OUTPUT_PREFIX prefix``
    May be used in conjunction with ``OUTPUT_DIR``.
    If specified, ``prefix`` is added to each output file name, like so
    ``--out dir/prefix<test_name>``.

  ``OUTPUT_SUFFIX suffix``
    May be used in conjunction with ``OUTPUT_DIR``.
    If specified, ``suffix`` is added to each output file name, like so
    ``--out dir/<test_name>suffix``. This can be used to add a file extension to
    the output e.g. ".xml".

#]=======================================================================]

#------------------------------------------------------------------------------
function(catch_discover_tests TARGET)
  cmake_parse_arguments(
    ""
    ""
    "TEST_PREFIX;TEST_SUFFIX;WORKING_DIRECTORY;TEST_LIST;REPORTER;OUTPUT_DIR;OUTPUT_PREFIX;OUTPUT_SUFFIX"
    "TEST_SPEC;EXTRA_ARGS;PROPERTIES"
    ${ARGN}
  )

  if(NOT _WORKING_DIRECTORY)
    set(_WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
  endif()
  if(NOT _TEST_LIST)
    set(_TEST_LIST ${TARGET}_TESTS)
  endif()

  ## Generate a unique name based on the extra arguments
  string(SHA1 args_hash "${_TEST_SPEC} ${_EXTRA_ARGS} ${_REPORTER} ${_OUTPUT_DIR} ${_OUTPUT_PREFIX} ${_OUTPUT_SUFFIX}")
  string(SUBSTRING ${args_hash} 0 7 args_hash)

  # Define rule to generate test list for aforementioned test executable
  set(ctest_include_file "${CMAKE_CURRENT_BINARY_DIR}/${TARGET}_include-${args_hash}.cmake")
  set(ctest_tests_file "${CMAKE_CURRENT_BINARY_DIR}/${TARGET}_tests-${args_hash}.cmake")
  get_property(crosscompiling_emulator
    TARGET ${TARGET}
    PROPERTY CROSSCOMPILING_EMULATOR
  )
  add_custom_command(
    TARGET ${TARGET} POST_BUILD
    BYPRODUCTS "${ctest_tests_file}"
    COMMAND "${CMAKE_COMMAND}"
            -D "TEST_TARGET=${TARGET}"
            -D "TEST_EXECUTABLE=$<TARGET_FILE:${TARGET}>"
            -D "TEST_EXECUTOR=${crosscompiling_emulator}"
            -D "TEST_WORKING_DIR=${_WORKING_DIRECTORY}"
            -D "TEST_SPEC=${_TEST_SPEC}"
            -D "TEST_EXTRA_ARGS=${_EXTRA_ARGS}"
            -D "TEST_PROPERTIES=${_PROPERTIES}"
            -D "TEST_PREFIX=${_TEST_PREFIX}"
            -D "TEST_SUFFIX=${_TEST_SUFFIX}"
            -D "TEST_LIST=${_TEST_LIST}"
            -D "TEST_REPORTER=${_REPORTER}"
            -D "TEST_OUTPUT_DIR=${_OUTPUT_DIR}"
            -D "TEST_OUTPUT_PREFIX=${_OUTPUT_PREFIX}"
            -D "TEST_OUTPUT_SUFFIX=${_OUTPUT_SUFFIX}"
            -D "CTEST_FILE=${ctest_tests_file}"
            -P "${_CATCH_DISCOVER_TESTS_SCRIPT}"
    VERBATIM
  )

  file(WRITE "${ctest_include_file}"
    "if(EXISTS \"${ctest_tests_file}\")\n"
    "  include(\"${ctest_tests_file}\")\n"
    "else()\n"
    "  add_test(${TARGET}_NOT_BUILT-${args_hash} ${TARGET}_NOT_BUILT-${args_hash})\n"
    "endif()\n"
  )

  if(NOT ${CMAKE_VERSION} VERSION_LESS "3.10.0") 
    # Add discovered tests to directory TEST_INCLUDE_FILES
    set_property(DIRECTORY
      APPEND PROPERTY TEST_INCLUDE_FILES "${ctest_include_file}"
    )
  else()
    # Add discovered tests as directory TEST_INCLUDE_FILE if possible
    get_property(test_include_file_set DIRECTORY PROPERTY TEST_INCLUDE_FILE SET)
    if (NOT ${test_include_file_set})
      set_property(DIRECTORY
        PROPERTY TEST_INCLUDE_FILE "${ctest_include_file}"
      )
    else()
      message(FATAL_ERROR
        "Cannot set more than one TEST_INCLUDE_FILE"
      )
    endif()
  endif()

endfunction()

###############################################################################

set(_CATCH_DISCOVER_TESTS_SCRIPT
  ${CMAKE_CURRENT_LIST_DIR}/CatchAddTests.cmake
)
