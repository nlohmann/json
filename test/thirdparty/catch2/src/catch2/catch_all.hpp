
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
/** \file
 * This is a convenience header for Catch2. It includes **all** of Catch2 headers.
 *
 * Generally the Catch2 users should use specific includes they need,
 * but this header can be used instead for ease-of-experimentation, or
 * just plain convenience, at the cost of (significantly) increased
 * compilation times.
 *
 * When a new header is added to either the top level folder, or to the
 * corresponding internal subfolder, it should be added here. Headers
 * added to the various subparts (e.g. matchers, generators, etc...),
 * should go their respective catch-all headers.
 */

#ifndef CATCH_ALL_HPP_INCLUDED
#define CATCH_ALL_HPP_INCLUDED

#include <catch2/benchmark/catch_benchmark_all.hpp>
#include <catch2/catch_approx.hpp>
#include <catch2/catch_assertion_info.hpp>
#include <catch2/catch_assertion_result.hpp>
#include <catch2/catch_config.hpp>
#include <catch2/catch_message.hpp>
#include <catch2/catch_reporter_registrars.hpp>
#include <catch2/catch_section_info.hpp>
#include <catch2/catch_session.hpp>
#include <catch2/catch_tag_alias.hpp>
#include <catch2/catch_tag_alias_autoregistrar.hpp>
#include <catch2/catch_template_test_macros.hpp>
#include <catch2/catch_test_case_info.hpp>
#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_test_spec.hpp>
#include <catch2/catch_timer.hpp>
#include <catch2/catch_tostring.hpp>
#include <catch2/catch_totals.hpp>
#include <catch2/catch_translate_exception.hpp>
#include <catch2/catch_version.hpp>
#include <catch2/catch_version_macros.hpp>
#include <catch2/generators/catch_generators_all.hpp>
#include <catch2/interfaces/catch_interfaces_all.hpp>
#include <catch2/internal/catch_assertion_handler.hpp>
#include <catch2/internal/catch_case_sensitive.hpp>
#include <catch2/internal/catch_clara.hpp>
#include <catch2/internal/catch_commandline.hpp>
#include <catch2/internal/catch_common.hpp>
#include <catch2/internal/catch_compiler_capabilities.hpp>
#include <catch2/internal/catch_config_uncaught_exceptions.hpp>
#include <catch2/internal/catch_console_colour.hpp>
#include <catch2/internal/catch_console_width.hpp>
#include <catch2/internal/catch_container_nonmembers.hpp>
#include <catch2/internal/catch_context.hpp>
#include <catch2/internal/catch_debug_console.hpp>
#include <catch2/internal/catch_debugger.hpp>
#include <catch2/internal/catch_decomposer.hpp>
#include <catch2/internal/catch_enforce.hpp>
#include <catch2/internal/catch_enum_values_registry.hpp>
#include <catch2/internal/catch_errno_guard.hpp>
#include <catch2/internal/catch_exception_translator_registry.hpp>
#include <catch2/internal/catch_fatal_condition_handler.hpp>
#include <catch2/internal/catch_lazy_expr.hpp>
#include <catch2/internal/catch_leak_detector.hpp>
#include <catch2/internal/catch_list.hpp>
#include <catch2/internal/catch_message_info.hpp>
#include <catch2/internal/catch_meta.hpp>
#include <catch2/internal/catch_noncopyable.hpp>
#include <catch2/internal/catch_option.hpp>
#include <catch2/internal/catch_output_redirect.hpp>
#include <catch2/internal/catch_platform.hpp>
#include <catch2/internal/catch_polyfills.hpp>
#include <catch2/internal/catch_preprocessor.hpp>
#include <catch2/internal/catch_random_number_generator.hpp>
#include <catch2/internal/catch_reporter_registry.hpp>
#include <catch2/internal/catch_result_type.hpp>
#include <catch2/internal/catch_run_context.hpp>
#include <catch2/internal/catch_section.hpp>
#include <catch2/internal/catch_singletons.hpp>
#include <catch2/internal/catch_startup_exception_registry.hpp>
#include <catch2/internal/catch_stream.hpp>
#include <catch2/internal/catch_string_manip.hpp>
#include <catch2/internal/catch_stringref.hpp>
#include <catch2/internal/catch_tag_alias_registry.hpp>
#include <catch2/internal/catch_template_test_registry.hpp>
#include <catch2/internal/catch_test_case_registry_impl.hpp>
#include <catch2/internal/catch_test_case_tracker.hpp>
#include <catch2/internal/catch_test_macro_impl.hpp>
#include <catch2/internal/catch_test_registry.hpp>
#include <catch2/internal/catch_test_spec_parser.hpp>
#include <catch2/internal/catch_textflow.hpp>
#include <catch2/internal/catch_to_string.hpp>
#include <catch2/internal/catch_uncaught_exceptions.hpp>
#include <catch2/internal/catch_unique_ptr.hpp>
#include <catch2/internal/catch_wildcard_pattern.hpp>
#include <catch2/internal/catch_windows_h_proxy.hpp>
#include <catch2/internal/catch_xmlwriter.hpp>
#include <catch2/matchers/catch_matchers_all.hpp>
#include <catch2/reporters/catch_reporters_all.hpp>

#endif // CATCH_ALL_HPP_INCLUDED
