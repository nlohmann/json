#pragma once

// This file contains all macro definitions affecting the ABI

#ifndef JSON_DIAGNOSTICS
    #define JSON_DIAGNOSTICS 0
#endif

#ifndef JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON
    #define JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON 0
#endif

#if JSON_DIAGNOSTICS
    #define NLOHMANN_JSON_ABI_TAG_DIAGNOSTICS _diag
#else
    #define NLOHMANN_JSON_ABI_TAG_DIAGNOSTICS
#endif

#if JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON
    #define NLOHMANN_JSON_ABI_TAG_LEGACY_DISCARDED_VALUE_COMPARISON _ldvcmp
#else
    #define NLOHMANN_JSON_ABI_TAG_LEGACY_DISCARDED_VALUE_COMPARISON
#endif

#define NLOHMANN_JSON_ABI_PREFIX json_v3_10_5
#define NLOHMANN_JSON_ABI_CONCAT_EX(a, b, c) a ## b ## c
#define NLOHMANN_JSON_ABI_CONCAT(a, b, c) NLOHMANN_JSON_ABI_CONCAT_EX(a, b, c)
#define NLOHMANN_JSON_ABI_STRING                                    \
    NLOHMANN_JSON_ABI_CONCAT(                                       \
            NLOHMANN_JSON_ABI_PREFIX,                               \
            NLOHMANN_JSON_ABI_TAG_DIAGNOSTICS,                      \
            NLOHMANN_JSON_ABI_TAG_LEGACY_DISCARDED_VALUE_COMPARISON \
                            )

#ifndef NLOHMANN_JSON_NAMESPACE
    #define NLOHMANN_JSON_NAMESPACE nlohmann::NLOHMANN_JSON_ABI_STRING
#endif

#ifndef NLOHMANN_JSON_NAMESPACE_BEGIN
#define NLOHMANN_JSON_NAMESPACE_BEGIN         \
    namespace nlohmann                        \
    {                                         \
    inline namespace NLOHMANN_JSON_ABI_STRING \
    {
#endif

#ifndef NLOHMANN_JSON_NAMESPACE_END
#define NLOHMANN_JSON_NAMESPACE_END \
    }  /* namespace (abi_string) */ \
    }  /* namespace nlohmann */
#endif
