//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <array>  // array, used for aligned storage of the empty singletons
#include <new>    // placement new

#include <nlohmann/detail/abi_macros.hpp>
#include <nlohmann/detail/value_t.hpp>

// -----------------------------------------------------------------------------
// Local exception-handling shim.
//
// The library-wide JSON_TRY / JSON_INTERNAL_CATCH macros are intentionally
// undef'd at the end of <nlohmann/json.hpp> via macro_unscope.hpp, so they are
// not visible to consumers that include this header after json.hpp. Define a
// header-private equivalent that respects JSON_NOEXCEPTION the same way.
// -----------------------------------------------------------------------------
#if (defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)) && !defined(JSON_NOEXCEPTION)
    #define NLOHMANN_EVAL_TRY            try
    #define NLOHMANN_EVAL_CATCH_ALL      catch (...)
#else
    #define NLOHMANN_EVAL_TRY            if (true)
    #define NLOHMANN_EVAL_CATCH_ALL      if (false)
#endif

NLOHMANN_JSON_NAMESPACE_BEGIN

// =============================================================================
// Null-safe, noexcept accessors (see discussion #5129)
//
// These free functions provide null-safe, noexcept access to JSON values.
// They never throw -- on any non-matching condition (the receiver is not an
// object, the key/pointer is missing, the resolved value is null, or it has
// the wrong type) they silently fall back to the supplied default value (for
// `eval_value`) or to a static empty array/object (for `eval_array` /
// `eval_object`).
//
// The non-member form is preferred over additional members on `basic_json`:
//   * it relies only on the public API (`is_object`, `is_array`, `is_null`,
//     `find`, `end`, `get`, `at(json_pointer)`);
//   * it does not enlarge the (already large) `basic_json` interface;
//   * it is fully resolvable via ADL (`eval_value(j, "a", 0)`);
//   * it lives in an opt-in header so users who do not need it pay nothing.
//
// Example:
//   auto j = from_server();                                  // may be null
//   int  a = nlohmann::eval_value(j, "a", 0);                // safe
//   auto d = nlohmann::eval_value(j,
//                                 "/c/d"_json_pointer,
//                                 std::string{});            // safe
//   for (const auto& item : nlohmann::eval_array(j, "items")) { /* ... */ }
// =============================================================================

namespace detail
{

// Singleton holding an immortalized empty JSON value of a given value_t.
//
// Implementation note: a plain `static const BasicJsonType instance(Kind);`
// would trigger Clang's -Wexit-time-destructors (which the project treats as
// an error). Instead we construct the value once into properly-aligned
// uninitialized storage via placement-new and return a reference to it. The
// destructor is intentionally never invoked at process exit, which is safe
// for an empty `array`/`object` constant: it owns no resources beyond the
// internal allocator state, and skipping its destructor avoids any
// static-destruction-order concerns.
//
// NOLINTBEGIN(bugprone-exception-escape) -- BasicJsonType's default-allocator
//   constructor is non-throwing in practice for the array/object value_t we
//   instantiate this with; the noexcept here is the contract callers rely on.
template<typename BasicJsonType, value_t Kind>
const BasicJsonType& empty_json_singleton() noexcept
{
    // Aligned, fixed-size byte storage holding the immortalized
    // BasicJsonType. Using std::array (rather than a C-style array)
    // avoids `cppcoreguidelines-avoid-c-arrays` warnings and the matching
    // flawfinder `buffer/char` heuristic.
    using storage_t = std::array<unsigned char, sizeof(BasicJsonType)>;
    alignas(BasicJsonType) static storage_t storage{};

    // Construct-once on first call. The pointer's type is a raw pointer
    // (trivially destructible), so this static local also does not require
    // an exit-time destructor.
    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory) -- intentional process-lifetime singleton
    static const BasicJsonType* const instance =
        ::new (static_cast<void*>(storage.data())) BasicJsonType(Kind);

    return *instance;
}
// NOLINTEND(bugprone-exception-escape)

}  // namespace detail

// -----------------------------------------------------------------------------
// eval_value -- noexcept value access with default
// -----------------------------------------------------------------------------

/// @brief access a value by key with a default fallback (noexcept)
///
/// Returns @a default_value if any of the following holds:
///   - @a j is not an object (null, array, string, number, boolean, ...);
///   - @a j is an object but @a key is missing;
///   - the value at @a key is null;
///   - the value at @a key cannot be converted to @c ValueType.
///
/// Never throws.
template<class BasicJsonType, class ValueType>
ValueType eval_value(const BasicJsonType& j,
                     const typename BasicJsonType::object_t::key_type& key,
                     const ValueType& default_value) noexcept
{
    if (!j.is_object())
    {
        return default_value;
    }

    NLOHMANN_EVAL_TRY
    {
        const auto it = j.find(key);
        if (it != j.end() && !it->is_null())
        {
            return it->template get<ValueType>();
        }
    }
    NLOHMANN_EVAL_CATCH_ALL {}

    return default_value;
}

/// @brief access a value by JSON Pointer with a default fallback (noexcept)
///
/// Returns @a default_value if any of the following holds:
///   - @a j is not an object;
///   - any segment of @a ptr cannot be resolved (missing, wrong type, ...);
///   - the resolved value is null;
///   - the resolved value cannot be converted to @c ValueType.
///
/// Never throws.
template<class BasicJsonType, class ValueType>
ValueType eval_value(const BasicJsonType& j,
                     const typename BasicJsonType::json_pointer& ptr,
                     const ValueType& default_value) noexcept
{
    if (!j.is_object())
    {
        return default_value;
    }

    NLOHMANN_EVAL_TRY
    {
        if (!j.contains(ptr))
        {
            return default_value;
        }
        const auto& resolved = j.at(ptr);
        if (resolved.is_null())
        {
            return default_value;
        }
        return resolved.template get<ValueType>();
    }
    NLOHMANN_EVAL_CATCH_ALL
    {
        return default_value;
    }
}

// -----------------------------------------------------------------------------
// eval_array -- noexcept array access (returns a const reference)
// -----------------------------------------------------------------------------

/// @brief access an array by key (noexcept)
///
/// Returns a const reference to the array stored at @a key. Returns a const
/// reference to a static empty array if any of the following holds:
///   - @a j is not an object;
///   - @a key is missing;
///   - the value at @a key is not an array.
///
/// Never throws.
template<class BasicJsonType>
const BasicJsonType& eval_array(
    const BasicJsonType& j,
    const typename BasicJsonType::object_t::key_type& key) noexcept
{
    const auto& empty = detail::empty_json_singleton<BasicJsonType, detail::value_t::array>();

    if (!j.is_object())
    {
        return empty;
    }

    NLOHMANN_EVAL_TRY
    {
        const auto it = j.find(key);
        if (it != j.end() && it->is_array())
        {
            return *it;
        }
    }
    NLOHMANN_EVAL_CATCH_ALL {}

    return empty;
}

/// @brief access an array by JSON Pointer (noexcept)
///
/// Returns a const reference to the array resolved by @a ptr. Returns a const
/// reference to a static empty array if any of the following holds:
///   - @a j is not an object;
///   - @a ptr cannot be resolved;
///   - the resolved value is not an array.
///
/// Never throws.
template<class BasicJsonType>
const BasicJsonType& eval_array(
    const BasicJsonType& j,
    const typename BasicJsonType::json_pointer& ptr) noexcept
{
    const auto& empty = detail::empty_json_singleton<BasicJsonType, detail::value_t::array>();

    if (!j.is_object())
    {
        return empty;
    }

    NLOHMANN_EVAL_TRY
    {
        if (!j.contains(ptr))
        {
            return empty;
        }
        const auto& resolved = j.at(ptr);
        if (resolved.is_array())
        {
            return resolved;
        }
    }
    NLOHMANN_EVAL_CATCH_ALL {}

    return empty;
}

// -----------------------------------------------------------------------------
// eval_object -- noexcept object access (returns a const reference)
// -----------------------------------------------------------------------------

/// @brief access an object by key (noexcept)
///
/// Returns a const reference to the object stored at @a key. Returns a const
/// reference to a static empty object if any of the following holds:
///   - @a j is not an object;
///   - @a key is missing;
///   - the value at @a key is not an object.
///
/// Never throws.
template<class BasicJsonType>
const BasicJsonType& eval_object(
    const BasicJsonType& j,
    const typename BasicJsonType::object_t::key_type& key) noexcept
{
    const auto& empty = detail::empty_json_singleton<BasicJsonType, detail::value_t::object>();

    if (!j.is_object())
    {
        return empty;
    }

    NLOHMANN_EVAL_TRY
    {
        const auto it = j.find(key);
        if (it != j.end() && it->is_object())
        {
            return *it;
        }
    }
    NLOHMANN_EVAL_CATCH_ALL {}

    return empty;
}

/// @brief access an object by JSON Pointer (noexcept)
///
/// Returns a const reference to the object resolved by @a ptr. Returns a const
/// reference to a static empty object if any of the following holds:
///   - @a j is not an object;
///   - @a ptr cannot be resolved;
///   - the resolved value is not an object.
///
/// Never throws.
template<class BasicJsonType>
const BasicJsonType& eval_object(
    const BasicJsonType& j,
    const typename BasicJsonType::json_pointer& ptr) noexcept
{
    const auto& empty = detail::empty_json_singleton<BasicJsonType, detail::value_t::object>();

    if (!j.is_object())
    {
        return empty;
    }

    NLOHMANN_EVAL_TRY
    {
        if (!j.contains(ptr))
        {
            return empty;
        }
        const auto& resolved = j.at(ptr);
        if (resolved.is_object())
        {
            return resolved;
        }
    }
    NLOHMANN_EVAL_CATCH_ALL {}

    return empty;
}

NLOHMANN_JSON_NAMESPACE_END

#undef NLOHMANN_EVAL_TRY
#undef NLOHMANN_EVAL_CATCH_ALL
