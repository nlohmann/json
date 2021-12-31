include(MiscFunctions)

# Please keep these ordered alphabetically
set(BENCHMARK_HEADERS
    ${SOURCES_DIR}/benchmark/catch_benchmark.hpp
    ${SOURCES_DIR}/benchmark/catch_benchmark_all.hpp
    ${SOURCES_DIR}/benchmark/catch_chronometer.hpp
    ${SOURCES_DIR}/benchmark/catch_clock.hpp
    ${SOURCES_DIR}/benchmark/catch_constructor.hpp
    ${SOURCES_DIR}/benchmark/catch_environment.hpp
    ${SOURCES_DIR}/benchmark/catch_estimate.hpp
    ${SOURCES_DIR}/benchmark/catch_execution_plan.hpp
    ${SOURCES_DIR}/benchmark/catch_optimizer.hpp
    ${SOURCES_DIR}/benchmark/catch_outlier_classification.hpp
    ${SOURCES_DIR}/benchmark/catch_sample_analysis.hpp
    ${SOURCES_DIR}/benchmark/detail/catch_analyse.hpp
    ${SOURCES_DIR}/benchmark/detail/catch_benchmark_function.hpp
    ${SOURCES_DIR}/benchmark/detail/catch_complete_invoke.hpp
    ${SOURCES_DIR}/benchmark/detail/catch_estimate_clock.hpp
    ${SOURCES_DIR}/benchmark/detail/catch_measure.hpp
    ${SOURCES_DIR}/benchmark/detail/catch_repeat.hpp
    ${SOURCES_DIR}/benchmark/detail/catch_run_for_at_least.hpp
    ${SOURCES_DIR}/benchmark/detail/catch_stats.hpp
    ${SOURCES_DIR}/benchmark/detail/catch_timing.hpp
)
set(BENCHMARK_SOURCES
    ${SOURCES_DIR}/benchmark/internal/catch_benchmark_combined_tu.cpp
    ${SOURCES_DIR}/benchmark/detail/catch_stats.cpp
)

SOURCE_GROUP("benchmark" FILES ${BENCHMARK_HEADERS} ${BENCHMARK_SOURCES})

set(INTERNAL_HEADERS
    ${SOURCES_DIR}/catch_all.hpp
    ${SOURCES_DIR}/matchers/catch_matchers_all.hpp
    ${SOURCES_DIR}/generators/catch_generators_all.hpp
    ${SOURCES_DIR}/interfaces/catch_interfaces_all.hpp
    ${SOURCES_DIR}/matchers/internal/catch_matchers_impl.hpp
    ${SOURCES_DIR}/internal/catch_console_width.hpp
    ${SOURCES_DIR}/internal/catch_container_nonmembers.hpp
    ${SOURCES_DIR}/internal/catch_noncopyable.hpp
    ${SOURCES_DIR}/catch_approx.hpp
    ${SOURCES_DIR}/internal/catch_assertion_handler.hpp
    ${SOURCES_DIR}/catch_assertion_info.hpp
    ${SOURCES_DIR}/catch_assertion_result.hpp
    ${SOURCES_DIR}/internal/catch_test_macro_impl.hpp
    ${SOURCES_DIR}/internal/catch_case_sensitive.hpp
    ${SOURCES_DIR}/internal/catch_clara.hpp
    ${SOURCES_DIR}/internal/catch_commandline.hpp
    ${SOURCES_DIR}/internal/catch_common.hpp
    ${SOURCES_DIR}/internal/catch_compiler_capabilities.hpp
    ${SOURCES_DIR}/catch_config.hpp
    ${SOURCES_DIR}/internal/catch_config_uncaught_exceptions.hpp
    ${SOURCES_DIR}/internal/catch_console_colour.hpp
    ${SOURCES_DIR}/internal/catch_context.hpp
    ${SOURCES_DIR}/internal/catch_debug_console.hpp
    ${SOURCES_DIR}/internal/catch_debugger.hpp
    ${SOURCES_DIR}/internal/catch_decomposer.hpp
    ${SOURCES_DIR}/internal/catch_enforce.hpp
    ${SOURCES_DIR}/internal/catch_enum_values_registry.hpp
    ${SOURCES_DIR}/internal/catch_errno_guard.hpp
    ${SOURCES_DIR}/internal/catch_exception_translator_registry.hpp
    ${SOURCES_DIR}/internal/catch_fatal_condition_handler.hpp
    ${SOURCES_DIR}/generators/catch_generator_exception.hpp
    ${SOURCES_DIR}/generators/catch_generators.hpp
    ${SOURCES_DIR}/generators/catch_generators_adapters.hpp
    ${SOURCES_DIR}/generators/catch_generators_random.hpp
    ${SOURCES_DIR}/generators/catch_generators_range.hpp
    ${SOURCES_DIR}/interfaces/catch_interfaces_capture.hpp
    ${SOURCES_DIR}/interfaces/catch_interfaces_config.hpp
    ${SOURCES_DIR}/interfaces/catch_interfaces_enum_values_registry.hpp
    ${SOURCES_DIR}/interfaces/catch_interfaces_exception.hpp
    ${SOURCES_DIR}/interfaces/catch_interfaces_generatortracker.hpp
    ${SOURCES_DIR}/interfaces/catch_interfaces_registry_hub.hpp
    ${SOURCES_DIR}/interfaces/catch_interfaces_reporter.hpp
    ${SOURCES_DIR}/interfaces/catch_interfaces_reporter_factory.hpp
    ${SOURCES_DIR}/interfaces/catch_interfaces_reporter_registry.hpp
    ${SOURCES_DIR}/interfaces/catch_interfaces_runner.hpp
    ${SOURCES_DIR}/interfaces/catch_interfaces_tag_alias_registry.hpp
    ${SOURCES_DIR}/interfaces/catch_interfaces_testcase.hpp
    ${SOURCES_DIR}/internal/catch_lazy_expr.hpp
    ${SOURCES_DIR}/internal/catch_leak_detector.hpp
    ${SOURCES_DIR}/internal/catch_list.hpp
    ${SOURCES_DIR}/matchers/catch_matchers.hpp
    ${SOURCES_DIR}/matchers/catch_matchers_container_properties.hpp
    ${SOURCES_DIR}/matchers/catch_matchers_contains.hpp
    ${SOURCES_DIR}/matchers/catch_matchers_exception.hpp
    ${SOURCES_DIR}/matchers/catch_matchers_floating.hpp
    ${SOURCES_DIR}/matchers/catch_matchers_predicate.hpp
    ${SOURCES_DIR}/matchers/catch_matchers_string.hpp
    ${SOURCES_DIR}/matchers/catch_matchers_templated.hpp
    ${SOURCES_DIR}/matchers/catch_matchers_vector.hpp
    ${SOURCES_DIR}/catch_message.hpp
    ${SOURCES_DIR}/internal/catch_message_info.hpp
    ${SOURCES_DIR}/internal/catch_meta.hpp
    ${SOURCES_DIR}/internal/catch_option.hpp
    ${SOURCES_DIR}/internal/catch_output_redirect.hpp
    ${SOURCES_DIR}/internal/catch_platform.hpp
    ${SOURCES_DIR}/internal/catch_polyfills.hpp
    ${SOURCES_DIR}/internal/catch_preprocessor.hpp
    ${SOURCES_DIR}/internal/catch_random_number_generator.hpp
    ${SOURCES_DIR}/catch_reporter_registrars.hpp
    ${SOURCES_DIR}/internal/catch_reporter_registry.hpp
    ${SOURCES_DIR}/internal/catch_result_type.hpp
    ${SOURCES_DIR}/internal/catch_run_context.hpp
    ${SOURCES_DIR}/internal/catch_section.hpp
    ${SOURCES_DIR}/catch_section_info.hpp
    ${SOURCES_DIR}/catch_session.hpp
    ${SOURCES_DIR}/internal/catch_singletons.hpp
    ${SOURCES_DIR}/internal/catch_startup_exception_registry.hpp
    ${SOURCES_DIR}/internal/catch_stream.hpp
    ${SOURCES_DIR}/internal/catch_string_manip.hpp
    ${SOURCES_DIR}/internal/catch_stringref.hpp
    ${SOURCES_DIR}/catch_tag_alias.hpp
    ${SOURCES_DIR}/catch_tag_alias_autoregistrar.hpp
    ${SOURCES_DIR}/internal/catch_tag_alias_registry.hpp
    ${SOURCES_DIR}/catch_test_case_info.hpp
    ${SOURCES_DIR}/internal/catch_test_case_registry_impl.hpp
    ${SOURCES_DIR}/internal/catch_test_case_tracker.hpp
    ${SOURCES_DIR}/catch_template_test_macros.hpp
    ${SOURCES_DIR}/catch_test_macros.hpp
    ${SOURCES_DIR}/internal/catch_template_test_registry.hpp
    ${SOURCES_DIR}/internal/catch_test_registry.hpp
    ${SOURCES_DIR}/catch_test_spec.hpp
    ${SOURCES_DIR}/internal/catch_test_spec_parser.hpp
    ${SOURCES_DIR}/internal/catch_textflow.hpp
    ${SOURCES_DIR}/catch_timer.hpp
    ${SOURCES_DIR}/internal/catch_to_string.hpp
    ${SOURCES_DIR}/catch_tostring.hpp
    ${SOURCES_DIR}/catch_totals.hpp
    ${SOURCES_DIR}/catch_translate_exception.hpp
    ${SOURCES_DIR}/internal/catch_uncaught_exceptions.hpp
    ${SOURCES_DIR}/internal/catch_unique_ptr.hpp
    ${SOURCES_DIR}/catch_version.hpp
    ${SOURCES_DIR}/catch_version_macros.hpp
    ${SOURCES_DIR}/internal/catch_wildcard_pattern.hpp
    ${SOURCES_DIR}/internal/catch_windows_h_proxy.hpp
    ${SOURCES_DIR}/internal/catch_xmlwriter.hpp
)
set(IMPL_SOURCES
    ${SOURCES_DIR}/catch_approx.cpp
    ${SOURCES_DIR}/internal/catch_assertion_handler.cpp
    ${SOURCES_DIR}/catch_assertion_result.cpp
    ${SOURCES_DIR}/matchers/internal/catch_matchers_combined_tu.cpp
    ${SOURCES_DIR}/internal/catch_clara.cpp
    ${SOURCES_DIR}/internal/catch_commandline.cpp
    ${SOURCES_DIR}/internal/catch_common.cpp
    ${SOURCES_DIR}/catch_config.cpp
    ${SOURCES_DIR}/internal/catch_console_colour.cpp
    ${SOURCES_DIR}/internal/catch_context.cpp
    ${SOURCES_DIR}/internal/catch_debug_console.cpp
    ${SOURCES_DIR}/internal/catch_debugger.cpp
    ${SOURCES_DIR}/internal/catch_enforce.cpp
    ${SOURCES_DIR}/internal/catch_enum_values_registry.cpp
    ${SOURCES_DIR}/internal/catch_exception_translator_registry.cpp
    ${SOURCES_DIR}/internal/catch_fatal_condition_handler.cpp
    ${SOURCES_DIR}/generators/internal/catch_generators_combined_tu.cpp
    ${SOURCES_DIR}/interfaces/catch_interfaces_combined_tu.cpp
    ${SOURCES_DIR}/interfaces/catch_interfaces_reporter.cpp
    ${SOURCES_DIR}/internal/catch_list.cpp
    ${SOURCES_DIR}/matchers/catch_matchers_floating.cpp
    ${SOURCES_DIR}/matchers/catch_matchers_string.cpp
    ${SOURCES_DIR}/matchers/catch_matchers_templated.cpp
    ${SOURCES_DIR}/catch_message.cpp
    ${SOURCES_DIR}/internal/catch_output_redirect.cpp
    ${SOURCES_DIR}/catch_registry_hub.cpp
    ${SOURCES_DIR}/internal/catch_combined_tu.cpp
    ${SOURCES_DIR}/internal/catch_random_number_generator.cpp
    ${SOURCES_DIR}/internal/catch_reporter_registry.cpp
    ${SOURCES_DIR}/internal/catch_result_type.cpp
    ${SOURCES_DIR}/internal/catch_run_context.cpp
    ${SOURCES_DIR}/internal/catch_section.cpp
    ${SOURCES_DIR}/catch_session.cpp
    ${SOURCES_DIR}/internal/catch_singletons.cpp
    ${SOURCES_DIR}/internal/catch_stream.cpp
    ${SOURCES_DIR}/internal/catch_stringref.cpp
    ${SOURCES_DIR}/internal/catch_string_manip.cpp
    ${SOURCES_DIR}/internal/catch_tag_alias_registry.cpp
    ${SOURCES_DIR}/catch_test_case_info.cpp
    ${SOURCES_DIR}/internal/catch_test_case_registry_impl.cpp
    ${SOURCES_DIR}/internal/catch_test_case_tracker.cpp
    ${SOURCES_DIR}/internal/catch_test_registry.cpp
    ${SOURCES_DIR}/internal/catch_textflow.cpp
    ${SOURCES_DIR}/catch_test_spec.cpp
    ${SOURCES_DIR}/internal/catch_test_spec_parser.cpp
    ${SOURCES_DIR}/catch_timer.cpp
    ${SOURCES_DIR}/catch_tostring.cpp
    ${SOURCES_DIR}/catch_totals.cpp
    ${SOURCES_DIR}/catch_version.cpp
    ${SOURCES_DIR}/internal/catch_wildcard_pattern.cpp
    ${SOURCES_DIR}/internal/catch_xmlwriter.cpp
)
set(INTERNAL_FILES ${IMPL_SOURCES} ${INTERNAL_HEADERS})

# Please keep these ordered alphabetically
set(REPORTER_HEADERS
    ${SOURCES_DIR}/reporters/catch_reporters_all.hpp
    ${SOURCES_DIR}/reporters/catch_reporter_automake.hpp
    ${SOURCES_DIR}/reporters/catch_reporter_compact.hpp
    ${SOURCES_DIR}/reporters/catch_reporter_console.hpp
    ${SOURCES_DIR}/reporters/catch_reporter_cumulative_base.hpp
    ${SOURCES_DIR}/reporters/catch_reporter_event_listener.hpp
    ${SOURCES_DIR}/reporters/catch_reporter_helpers.hpp
    ${SOURCES_DIR}/reporters/catch_reporter_junit.hpp
    ${SOURCES_DIR}/reporters/catch_reporter_listening.hpp
    ${SOURCES_DIR}/reporters/catch_reporter_sonarqube.hpp
    ${SOURCES_DIR}/reporters/catch_reporter_streaming_base.hpp
    ${SOURCES_DIR}/reporters/catch_reporter_tap.hpp
    ${SOURCES_DIR}/reporters/catch_reporter_teamcity.hpp
    ${SOURCES_DIR}/reporters/catch_reporter_xml.hpp
)
set(REPORTER_SOURCES
    ${SOURCES_DIR}/reporters/catch_reporter_automake.cpp
    ${SOURCES_DIR}/reporters/catch_reporter_combined_tu.cpp
    ${SOURCES_DIR}/reporters/catch_reporter_compact.cpp
    ${SOURCES_DIR}/reporters/catch_reporter_console.cpp
    ${SOURCES_DIR}/reporters/catch_reporter_cumulative_base.cpp
    ${SOURCES_DIR}/reporters/catch_reporter_junit.cpp
    ${SOURCES_DIR}/reporters/catch_reporter_listening.cpp
    ${SOURCES_DIR}/reporters/catch_reporter_sonarqube.cpp
    ${SOURCES_DIR}/reporters/catch_reporter_streaming_base.cpp
    ${SOURCES_DIR}/reporters/catch_reporter_tap.cpp
    ${SOURCES_DIR}/reporters/catch_reporter_teamcity.cpp
    ${SOURCES_DIR}/reporters/catch_reporter_xml.cpp
)
set(REPORTER_FILES ${REPORTER_HEADERS} ${REPORTER_SOURCES})

# Fixme: STATIC because for dynamic, we would need to handle visibility
# and I don't want to do the annotations right now
add_library(Catch2 STATIC
  ${REPORTER_FILES}
  ${INTERNAL_FILES}
  ${BENCHMARK_HEADERS}
  ${BENCHMARK_SOURCES}
)
add_library(Catch2::Catch2 ALIAS Catch2)

if (ANDROID)
    target_link_libraries(Catch2 INTERFACE log)
endif()

# depend on bunch of C++11 and C++14 features to have C++14 enabled by default
target_compile_features(Catch2
  PUBLIC
    cxx_alignas
    cxx_alignof
    cxx_attributes
    cxx_auto_type
    cxx_constexpr
    cxx_defaulted_functions
    cxx_deleted_functions
    cxx_final
    cxx_lambdas
    cxx_noexcept
    cxx_override
    cxx_range_for
    cxx_rvalue_references
    cxx_static_assert
    cxx_strong_enums
    cxx_trailing_return_types
    cxx_unicode_literals
    cxx_user_literals
    cxx_variable_templates
    cxx_variadic_macros
)

target_include_directories(Catch2
  PUBLIC
    $<BUILD_INTERFACE:${SOURCES_DIR}/..>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)


add_library(Catch2WithMain STATIC
    ${SOURCES_DIR}/internal/catch_main.cpp
)
add_library(Catch2::Catch2WithMain ALIAS Catch2WithMain)
target_link_libraries(Catch2WithMain PUBLIC Catch2)
set_target_properties(Catch2WithMain
  PROPERTIES
    OUTPUT_NAME "Catch2Main"
)

if (NOT_SUBPROJECT)
    # create and install an export set for catch target as Catch2::Catch
    install(
      TARGETS
        Catch2
        Catch2WithMain
      EXPORT
        Catch2Targets
      DESTINATION
        ${CMAKE_INSTALL_LIBDIR}
    )


    install(
      EXPORT
        Catch2Targets
      NAMESPACE
        Catch2::
      DESTINATION
        ${CATCH_CMAKE_CONFIG_DESTINATION}
    )
    # Install the headers
    install(DIRECTORY ${SOURCES_DIR} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} FILES_MATCHING PATTERN "*.h*")
endif()

# Some tests require a full recompilation of Catch2 lib with different
# compilation flags. They can link against this target to recompile all
# the sources into the binary.
if (CATCH_BUILD_EXAMPLES OR CATCH_BUILD_EXTRA_TESTS)
    add_library(Catch2_buildall_interface INTERFACE)
    target_sources(Catch2_buildall_interface INTERFACE
      ${REPORTER_FILES}
      ${INTERNAL_FILES}
      ${BENCHMARK_HEADERS}
      ${BENCHMARK_SOURCES}
      # Also include main entry point
      ${SOURCES_DIR}/internal/catch_main.cpp
    )
    target_include_directories(Catch2_buildall_interface
      INTERFACE
        $<BUILD_INTERFACE:${SOURCES_DIR}/..>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    )
    target_compile_features(Catch2_buildall_interface
      INTERFACE
        cxx_alignas
        cxx_alignof
        cxx_attributes
        cxx_auto_type
        cxx_constexpr
        cxx_defaulted_functions
        cxx_deleted_functions
        cxx_final
        cxx_lambdas
        cxx_noexcept
        cxx_override
        cxx_range_for
        cxx_rvalue_references
        cxx_static_assert
        cxx_strong_enums
        cxx_trailing_return_types
        cxx_unicode_literals
        cxx_user_literals
        cxx_variable_templates
        cxx_variadic_macros
    )
endif()

list(APPEND CATCH_WARNING_TARGETS Catch2 Catch2WithMain)
set(CATCH_WARNING_TARGETS ${CATCH_WARNING_TARGETS} PARENT_SCOPE)
