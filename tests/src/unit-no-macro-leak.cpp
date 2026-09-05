//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// This file makes sure that none of the internal JSON_HEDLEY_* macros (vendored
// from https://nemequ.github.io/hedley/, see
// include/nlohmann/thirdparty/hedley/hedley.hpp) leak into the including
// translation unit. include/nlohmann/detail/macro_unscope.hpp is supposed to
// #undef every JSON_HEDLEY_* macro (via hedley_undef.hpp) once json.hpp has
// been fully processed. See https://github.com/nlohmann/json/issues/5408,
// where JSON_HEDLEY_PRAGMA, JSON_HEDLEY_PREDICT_TRUE, JSON_HEDLEY_PREDICT_FALSE,
// and JSON_HEDLEY_CLANG_HAS_DECLSPEC_ATTRIBUTE escaped this cleanup because
// hedley_undef.hpp had no matching #undef for them.
//
// The #ifdef/#error checks below are mechanically derived from the full list
// of macro names in hedley_undef.hpp, so every JSON_HEDLEY_* macro is covered
// -- not just the four that leaked historically.

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>

#ifdef JSON_HEDLEY_ALWAYS_INLINE
    #error "JSON_HEDLEY_ALWAYS_INLINE must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_ARM_VERSION
    #error "JSON_HEDLEY_ARM_VERSION must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_ARM_VERSION_CHECK
    #error "JSON_HEDLEY_ARM_VERSION_CHECK must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_ARRAY_PARAM
    #error "JSON_HEDLEY_ARRAY_PARAM must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_ASSUME
    #error "JSON_HEDLEY_ASSUME must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_BEGIN_C_DECLS
    #error "JSON_HEDLEY_BEGIN_C_DECLS must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_CLANG_HAS_ATTRIBUTE
    #error "JSON_HEDLEY_CLANG_HAS_ATTRIBUTE must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_CLANG_HAS_BUILTIN
    #error "JSON_HEDLEY_CLANG_HAS_BUILTIN must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_CLANG_HAS_CPP_ATTRIBUTE
    #error "JSON_HEDLEY_CLANG_HAS_CPP_ATTRIBUTE must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_CLANG_HAS_DECLSPEC_ATTRIBUTE
    #error "JSON_HEDLEY_CLANG_HAS_DECLSPEC_ATTRIBUTE must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_CLANG_HAS_EXTENSION
    #error "JSON_HEDLEY_CLANG_HAS_EXTENSION must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_CLANG_HAS_FEATURE
    #error "JSON_HEDLEY_CLANG_HAS_FEATURE must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_CLANG_HAS_WARNING
    #error "JSON_HEDLEY_CLANG_HAS_WARNING must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_COMPCERT_VERSION
    #error "JSON_HEDLEY_COMPCERT_VERSION must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_COMPCERT_VERSION_CHECK
    #error "JSON_HEDLEY_COMPCERT_VERSION_CHECK must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_CONCAT
    #error "JSON_HEDLEY_CONCAT must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_CONCAT3
    #error "JSON_HEDLEY_CONCAT3 must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_CONCAT3_EX
    #error "JSON_HEDLEY_CONCAT3_EX must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_CONCAT_EX
    #error "JSON_HEDLEY_CONCAT_EX must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_CONST
    #error "JSON_HEDLEY_CONST must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_CONSTEXPR
    #error "JSON_HEDLEY_CONSTEXPR must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_CONST_CAST
    #error "JSON_HEDLEY_CONST_CAST must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_CPP_CAST
    #error "JSON_HEDLEY_CPP_CAST must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_CRAY_VERSION
    #error "JSON_HEDLEY_CRAY_VERSION must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_CRAY_VERSION_CHECK
    #error "JSON_HEDLEY_CRAY_VERSION_CHECK must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_C_DECL
    #error "JSON_HEDLEY_C_DECL must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_DEPRECATED
    #error "JSON_HEDLEY_DEPRECATED must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_DEPRECATED_FOR
    #error "JSON_HEDLEY_DEPRECATED_FOR must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_DIAGNOSTIC_DISABLE_CAST_QUAL
    #error "JSON_HEDLEY_DIAGNOSTIC_DISABLE_CAST_QUAL must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_
    #error "JSON_HEDLEY_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_ must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_DIAGNOSTIC_DISABLE_DEPRECATED
    #error "JSON_HEDLEY_DIAGNOSTIC_DISABLE_DEPRECATED must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNKNOWN_CPP_ATTRIBUTES
    #error "JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNKNOWN_CPP_ATTRIBUTES must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNKNOWN_PRAGMAS
    #error "JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNKNOWN_PRAGMAS must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNUSED_FUNCTION
    #error "JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNUSED_FUNCTION must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_DIAGNOSTIC_POP
    #error "JSON_HEDLEY_DIAGNOSTIC_POP must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_DIAGNOSTIC_PUSH
    #error "JSON_HEDLEY_DIAGNOSTIC_PUSH must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_DMC_VERSION
    #error "JSON_HEDLEY_DMC_VERSION must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_DMC_VERSION_CHECK
    #error "JSON_HEDLEY_DMC_VERSION_CHECK must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_EMPTY_BASES
    #error "JSON_HEDLEY_EMPTY_BASES must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_EMSCRIPTEN_VERSION
    #error "JSON_HEDLEY_EMSCRIPTEN_VERSION must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_EMSCRIPTEN_VERSION_CHECK
    #error "JSON_HEDLEY_EMSCRIPTEN_VERSION_CHECK must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_END_C_DECLS
    #error "JSON_HEDLEY_END_C_DECLS must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_FALL_THROUGH
    #error "JSON_HEDLEY_FALL_THROUGH must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_FLAGS
    #error "JSON_HEDLEY_FLAGS must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_FLAGS_CAST
    #error "JSON_HEDLEY_FLAGS_CAST must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_GCC_HAS_ATTRIBUTE
    #error "JSON_HEDLEY_GCC_HAS_ATTRIBUTE must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_GCC_HAS_BUILTIN
    #error "JSON_HEDLEY_GCC_HAS_BUILTIN must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_GCC_HAS_CPP_ATTRIBUTE
    #error "JSON_HEDLEY_GCC_HAS_CPP_ATTRIBUTE must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_GCC_HAS_DECLSPEC_ATTRIBUTE
    #error "JSON_HEDLEY_GCC_HAS_DECLSPEC_ATTRIBUTE must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_GCC_HAS_EXTENSION
    #error "JSON_HEDLEY_GCC_HAS_EXTENSION must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_GCC_HAS_FEATURE
    #error "JSON_HEDLEY_GCC_HAS_FEATURE must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_GCC_HAS_WARNING
    #error "JSON_HEDLEY_GCC_HAS_WARNING must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_GCC_NOT_CLANG_VERSION_CHECK
    #error "JSON_HEDLEY_GCC_NOT_CLANG_VERSION_CHECK must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_GCC_VERSION
    #error "JSON_HEDLEY_GCC_VERSION must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_GCC_VERSION_CHECK
    #error "JSON_HEDLEY_GCC_VERSION_CHECK must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_GNUC_HAS_ATTRIBUTE
    #error "JSON_HEDLEY_GNUC_HAS_ATTRIBUTE must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_GNUC_HAS_BUILTIN
    #error "JSON_HEDLEY_GNUC_HAS_BUILTIN must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_GNUC_HAS_CPP_ATTRIBUTE
    #error "JSON_HEDLEY_GNUC_HAS_CPP_ATTRIBUTE must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_GNUC_HAS_DECLSPEC_ATTRIBUTE
    #error "JSON_HEDLEY_GNUC_HAS_DECLSPEC_ATTRIBUTE must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_GNUC_HAS_EXTENSION
    #error "JSON_HEDLEY_GNUC_HAS_EXTENSION must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_GNUC_HAS_FEATURE
    #error "JSON_HEDLEY_GNUC_HAS_FEATURE must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_GNUC_HAS_WARNING
    #error "JSON_HEDLEY_GNUC_HAS_WARNING must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_GNUC_VERSION
    #error "JSON_HEDLEY_GNUC_VERSION must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_GNUC_VERSION_CHECK
    #error "JSON_HEDLEY_GNUC_VERSION_CHECK must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_HAS_ATTRIBUTE
    #error "JSON_HEDLEY_HAS_ATTRIBUTE must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_HAS_BUILTIN
    #error "JSON_HEDLEY_HAS_BUILTIN must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_HAS_CPP_ATTRIBUTE
    #error "JSON_HEDLEY_HAS_CPP_ATTRIBUTE must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_HAS_CPP_ATTRIBUTE_NS
    #error "JSON_HEDLEY_HAS_CPP_ATTRIBUTE_NS must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_HAS_DECLSPEC_ATTRIBUTE
    #error "JSON_HEDLEY_HAS_DECLSPEC_ATTRIBUTE must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_HAS_EXTENSION
    #error "JSON_HEDLEY_HAS_EXTENSION must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_HAS_FEATURE
    #error "JSON_HEDLEY_HAS_FEATURE must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_HAS_WARNING
    #error "JSON_HEDLEY_HAS_WARNING must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_IAR_VERSION
    #error "JSON_HEDLEY_IAR_VERSION must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_IAR_VERSION_CHECK
    #error "JSON_HEDLEY_IAR_VERSION_CHECK must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_IBM_VERSION
    #error "JSON_HEDLEY_IBM_VERSION must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_IBM_VERSION_CHECK
    #error "JSON_HEDLEY_IBM_VERSION_CHECK must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_IMPORT
    #error "JSON_HEDLEY_IMPORT must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_INLINE
    #error "JSON_HEDLEY_INLINE must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_INTEL_CL_VERSION
    #error "JSON_HEDLEY_INTEL_CL_VERSION must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_INTEL_CL_VERSION_CHECK
    #error "JSON_HEDLEY_INTEL_CL_VERSION_CHECK must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_INTEL_VERSION
    #error "JSON_HEDLEY_INTEL_VERSION must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_INTEL_VERSION_CHECK
    #error "JSON_HEDLEY_INTEL_VERSION_CHECK must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_IS_CONSTANT
    #error "JSON_HEDLEY_IS_CONSTANT must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_IS_CONSTEXPR_
    #error "JSON_HEDLEY_IS_CONSTEXPR_ must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_LIKELY
    #error "JSON_HEDLEY_LIKELY must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_MALLOC
    #error "JSON_HEDLEY_MALLOC must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_MCST_LCC_VERSION
    #error "JSON_HEDLEY_MCST_LCC_VERSION must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_MCST_LCC_VERSION_CHECK
    #error "JSON_HEDLEY_MCST_LCC_VERSION_CHECK must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_MESSAGE
    #error "JSON_HEDLEY_MESSAGE must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_MSVC_VERSION
    #error "JSON_HEDLEY_MSVC_VERSION must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_MSVC_VERSION_CHECK
    #error "JSON_HEDLEY_MSVC_VERSION_CHECK must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_NEVER_INLINE
    #error "JSON_HEDLEY_NEVER_INLINE must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_NON_NULL
    #error "JSON_HEDLEY_NON_NULL must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_NO_ESCAPE
    #error "JSON_HEDLEY_NO_ESCAPE must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_NO_RETURN
    #error "JSON_HEDLEY_NO_RETURN must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_NO_THROW
    #error "JSON_HEDLEY_NO_THROW must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_NULL
    #error "JSON_HEDLEY_NULL must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_PELLES_VERSION
    #error "JSON_HEDLEY_PELLES_VERSION must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_PELLES_VERSION_CHECK
    #error "JSON_HEDLEY_PELLES_VERSION_CHECK must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_PGI_VERSION
    #error "JSON_HEDLEY_PGI_VERSION must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_PGI_VERSION_CHECK
    #error "JSON_HEDLEY_PGI_VERSION_CHECK must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_PRAGMA
    #error "JSON_HEDLEY_PRAGMA must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_PREDICT
    #error "JSON_HEDLEY_PREDICT must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_PREDICT_FALSE
    #error "JSON_HEDLEY_PREDICT_FALSE must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_PREDICT_TRUE
    #error "JSON_HEDLEY_PREDICT_TRUE must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_PRINTF_FORMAT
    #error "JSON_HEDLEY_PRINTF_FORMAT must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_PRIVATE
    #error "JSON_HEDLEY_PRIVATE must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_PUBLIC
    #error "JSON_HEDLEY_PUBLIC must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_PURE
    #error "JSON_HEDLEY_PURE must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_REINTERPRET_CAST
    #error "JSON_HEDLEY_REINTERPRET_CAST must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_REQUIRE
    #error "JSON_HEDLEY_REQUIRE must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_REQUIRE_CONSTEXPR
    #error "JSON_HEDLEY_REQUIRE_CONSTEXPR must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_REQUIRE_MSG
    #error "JSON_HEDLEY_REQUIRE_MSG must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_RESTRICT
    #error "JSON_HEDLEY_RESTRICT must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_RETURNS_NON_NULL
    #error "JSON_HEDLEY_RETURNS_NON_NULL must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_SENTINEL
    #error "JSON_HEDLEY_SENTINEL must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_STATIC_ASSERT
    #error "JSON_HEDLEY_STATIC_ASSERT must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_STATIC_CAST
    #error "JSON_HEDLEY_STATIC_CAST must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_STRINGIFY
    #error "JSON_HEDLEY_STRINGIFY must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_STRINGIFY_EX
    #error "JSON_HEDLEY_STRINGIFY_EX must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_SUNPRO_VERSION
    #error "JSON_HEDLEY_SUNPRO_VERSION must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_SUNPRO_VERSION_CHECK
    #error "JSON_HEDLEY_SUNPRO_VERSION_CHECK must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_TINYC_VERSION
    #error "JSON_HEDLEY_TINYC_VERSION must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_TINYC_VERSION_CHECK
    #error "JSON_HEDLEY_TINYC_VERSION_CHECK must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_TI_ARMCL_VERSION
    #error "JSON_HEDLEY_TI_ARMCL_VERSION must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_TI_ARMCL_VERSION_CHECK
    #error "JSON_HEDLEY_TI_ARMCL_VERSION_CHECK must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_TI_CL2000_VERSION
    #error "JSON_HEDLEY_TI_CL2000_VERSION must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_TI_CL2000_VERSION_CHECK
    #error "JSON_HEDLEY_TI_CL2000_VERSION_CHECK must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_TI_CL430_VERSION
    #error "JSON_HEDLEY_TI_CL430_VERSION must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_TI_CL430_VERSION_CHECK
    #error "JSON_HEDLEY_TI_CL430_VERSION_CHECK must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_TI_CL6X_VERSION
    #error "JSON_HEDLEY_TI_CL6X_VERSION must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_TI_CL6X_VERSION_CHECK
    #error "JSON_HEDLEY_TI_CL6X_VERSION_CHECK must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_TI_CL7X_VERSION
    #error "JSON_HEDLEY_TI_CL7X_VERSION must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_TI_CL7X_VERSION_CHECK
    #error "JSON_HEDLEY_TI_CL7X_VERSION_CHECK must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_TI_CLPRU_VERSION
    #error "JSON_HEDLEY_TI_CLPRU_VERSION must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_TI_CLPRU_VERSION_CHECK
    #error "JSON_HEDLEY_TI_CLPRU_VERSION_CHECK must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_TI_VERSION
    #error "JSON_HEDLEY_TI_VERSION must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_TI_VERSION_CHECK
    #error "JSON_HEDLEY_TI_VERSION_CHECK must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_UNAVAILABLE
    #error "JSON_HEDLEY_UNAVAILABLE must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_UNLIKELY
    #error "JSON_HEDLEY_UNLIKELY must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_UNPREDICTABLE
    #error "JSON_HEDLEY_UNPREDICTABLE must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_UNREACHABLE
    #error "JSON_HEDLEY_UNREACHABLE must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_UNREACHABLE_RETURN
    #error "JSON_HEDLEY_UNREACHABLE_RETURN must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_VERSION
    #error "JSON_HEDLEY_VERSION must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_VERSION_DECODE_MAJOR
    #error "JSON_HEDLEY_VERSION_DECODE_MAJOR must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_VERSION_DECODE_MINOR
    #error "JSON_HEDLEY_VERSION_DECODE_MINOR must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_VERSION_DECODE_REVISION
    #error "JSON_HEDLEY_VERSION_DECODE_REVISION must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_VERSION_ENCODE
    #error "JSON_HEDLEY_VERSION_ENCODE must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_WARNING
    #error "JSON_HEDLEY_WARNING must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_WARN_UNUSED_RESULT
    #error "JSON_HEDLEY_WARN_UNUSED_RESULT must not remain defined after including json.hpp"
#endif
#ifdef JSON_HEDLEY_WARN_UNUSED_RESULT_MSG
    #error "JSON_HEDLEY_WARN_UNUSED_RESULT_MSG must not remain defined after including json.hpp"
#endif

TEST_CASE("no JSON_HEDLEY_* macro leaks after including json.hpp")
{
    // if this test compiles at all, none of the JSON_HEDLEY_* macros checked
    // above remained defined after including <nlohmann/json.hpp>
    CHECK(true);
}
