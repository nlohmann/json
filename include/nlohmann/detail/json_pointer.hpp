//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <algorithm> // all_of, copy
#include <array> // array
#include <cctype> // isdigit
#include <cerrno> // errno, ERANGE
#include <cstddef> // size_t
#include <cstdint> // uint64_t
#include <cstdlib> // strtoull
#include <cstring> // memchr, memcmp, memcpy
#ifndef JSON_NO_IO
    #include <iosfwd> // ostream
#endif  // JSON_NO_IO
#include <limits> // max
#include <string> // string
#include <utility> // move
#include <vector> // vector

#include <nlohmann/detail/exceptions.hpp>
#include <nlohmann/detail/macro_scope.hpp>
#include <nlohmann/detail/meta/cpp_future.hpp>
#include <nlohmann/detail/meta/type_traits.hpp>
#include <nlohmann/detail/string_concat.hpp>
#include <nlohmann/detail/string_escape.hpp>
#include <nlohmann/detail/string_utils.hpp>
#include <nlohmann/detail/value_t.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN

namespace detail
{
struct json_pointer_access;

/*!
@brief result of parse_array_index()

json_pointer::array_index() maps each value to the corresponding
parse_error/out_of_range exception; json_pointer::contains() and
get_checked_or_null(), which must not throw for an out-of-range or
unrepresentable index, and the json_view pointer resolution switch on it
directly instead.
*/
enum class array_index_status
{
    ok,                ///< @a s is a valid, representable array index
    leading_zero,      ///< @a s begins with '0' but has more than one character
    not_a_number,      ///< @a s is neither empty nor "-" and does not begin with a digit
    unresolved,        ///< @a s could not be converted to an integer
    exceeds_size_type  ///< @a s converts to an integer that exceeds SizeType
};

/*!
@brief convert a JSON Pointer reference token into an array index (RFC 6901, Sect. 4)

@param[in] s    reference token to be converted into an array index; its data()
                must be NUL-terminated
@param[out] idx the integer representation of @a s if array_index_status::ok
                is returned; left unchanged otherwise

@return whether @a s is a valid array index, and if not, why

@note this function never throws; json_pointer::array_index(), the callers that
      must not throw, and the json_view pointer resolution build on it instead
      of each re-implementing the RFC 6901 digit rules and the range check
@note force-inlined: as a free function template it is no longer inlined into
      the pointer resolution, which makes JsonPointerAt up to 17% slower (#5891)
*/
template<typename SizeType, typename StringType>
JSON_HEDLEY_ALWAYS_INLINE array_index_status parse_array_index(const StringType& s, SizeType& idx) noexcept
{
    // error condition (cf. RFC 6901, Sect. 4)
    if (JSON_HEDLEY_UNLIKELY(s.size() > 1 && s[0] == '0'))
    {
        return array_index_status::leading_zero;
    }

    // error condition (cf. RFC 6901, Sect. 4); this also covers single-
    // character tokens, so "/x" and "/xy" fail alike; "-" and the empty
    // token are left to the conversion below and are reported as unresolved
    if (JSON_HEDLEY_UNLIKELY(!s.empty() && !(s.size() == 1 && s[0] == '-') && !(s[0] >= '0' && s[0] <= '9')))
    {
        return array_index_status::not_a_number;
    }

    // fast path: up to 18 decimal digits cannot overflow unsigned long long or
    // SizeType (9 digits for a 32-bit SizeType), so strtoull and errno are not needed
    constexpr std::size_t max_fast_digits = sizeof(SizeType) >= 8 ? 18 : 9;
    if (!s.empty() && s.size() <= max_fast_digits)
    {
        SizeType acc = 0;
        for (std::size_t i = 0; i < s.size(); ++i)
        {
            const char c = s[i];
            if (JSON_HEDLEY_UNLIKELY(c < '0' || c > '9'))
            {
                break; // not a plain number: let strtoull decide
            }
            acc = static_cast<SizeType>((acc * 10) + static_cast<SizeType>(c - '0'));
            if (JSON_HEDLEY_UNLIKELY(i == s.size() - 1))
            {
                idx = acc;
                return array_index_status::ok;
            }
        }
    }

    const char* p = s.data();
    char* p_end = nullptr; // NOLINT(misc-const-correctness)
    errno = 0; // strtoull doesn't reset errno
    const unsigned long long res = std::strtoull(p, &p_end, 10); // NOLINT(runtime/int)
    if (p == p_end // invalid input or empty string
            || errno == ERANGE // out of range
            || JSON_HEDLEY_UNLIKELY(static_cast<std::size_t>(p_end - p) != s.size())) // incomplete read
    {
        return array_index_status::unresolved;
    }

    // the index does not fit into SizeType; on 64-bit platforms this is
    // only SIZE_MAX itself (see #2203 and #5395)
    if (res >= static_cast<unsigned long long>((std::numeric_limits<SizeType>::max)()))  // NOLINT(runtime/int)
    {
        return array_index_status::exceeds_size_type;
    }

    idx = static_cast<SizeType>(res);
    return array_index_status::ok;
}

}  // namespace detail

/// @brief JSON Pointer defines a string syntax for identifying a specific value within a JSON document
/// @sa https://json.nlohmann.me/api/json_pointer/
template<typename RefStringType>
class json_pointer
{
    // allow basic_json to access private members
    NLOHMANN_BASIC_JSON_TPL_DECLARATION
    friend class basic_json;

    template<typename>
    friend class json_pointer;

    friend struct detail::json_pointer_access;

    template<typename T>
    struct string_t_helper
    {
        using type = T;
    };

    NLOHMANN_BASIC_JSON_TPL_DECLARATION
    struct string_t_helper<NLOHMANN_BASIC_JSON_TPL>
    {
        using type = StringType;
    };

  public:
    // for backwards compatibility accept BasicJsonType
    using string_t = typename string_t_helper<RefStringType>::type;

    /// @brief create JSON pointer
    /// @sa https://json.nlohmann.me/api/json_pointer/json_pointer/
    explicit json_pointer(const string_t& s = "")
        : reference_tokens(split(s))
    {}

    /// @brief return a string representation of the JSON pointer
    /// @sa https://json.nlohmann.me/api/json_pointer/to_string/
    string_t to_string() const
    {
        if (reference_tokens.empty())
        {
            return string_t();
        }

        // one buffer: every token adds its escaped form (at least its length) and a slash
        std::size_t length = 0;
        bool plain = true;
        for (const auto& reference_token : reference_tokens)
        {
            length += reference_token.size() + 1;
            const char* const data = reference_token.data();
            for (std::size_t i = 0, size = reference_token.size(); plain && i < size; ++i)
            {
                plain = data[i] != '~' && data[i] != '/';
            }
        }

        string_t result;
        if (JSON_HEDLEY_LIKELY(plain))
        {
            // nothing to escape: the tokens are copied into the string
            result.resize(length);
            char* out = &result[0];
            for (const auto& reference_token : reference_tokens)
            {
                *out++ = '/';
                out = std::copy(reference_token.data(), reference_token.data() + reference_token.size(), out);
            }
            return result;
        }

        result.reserve(length);
        for (const auto& reference_token : reference_tokens)
        {
            result.append("/", 1);
            detail::escape_into(result, reference_token);
        }
        return result;
    }

    /// @brief return a string representation of the JSON pointer
    /// @sa https://json.nlohmann.me/api/json_pointer/operator_string_t/
    JSON_HEDLEY_DEPRECATED_FOR(3.11.0, to_string())
    operator string_t() const
#if JSON_DELETE_DEPRECATED_FUNCTIONS
        = delete;
#else
    {
        return to_string();
    }
#endif

#ifndef JSON_NO_IO
    /// @brief write string representation of the JSON pointer to stream
    /// @sa https://json.nlohmann.me/api/operator_ltlt/
    friend std::ostream& operator<<(std::ostream& o, const json_pointer& ptr)
    {
        o << ptr.to_string();
        return o;
    }
#endif

    /// @brief append another JSON pointer at the end of this JSON pointer
    /// @sa https://json.nlohmann.me/api/json_pointer/operator_slasheq/
    json_pointer& operator/=(const json_pointer& ptr)
    {
        reference_tokens.insert(reference_tokens.end(),
                                ptr.reference_tokens.begin(),
                                ptr.reference_tokens.end());
        return *this;
    }

    /// @brief append an unescaped reference token at the end of this JSON pointer
    /// @sa https://json.nlohmann.me/api/json_pointer/operator_slasheq/
    json_pointer& operator/=(string_t token)
    {
        push_back(std::move(token));
        return *this;
    }

    /// @brief append an array index at the end of this JSON pointer
    /// @sa https://json.nlohmann.me/api/json_pointer/operator_slasheq/
    json_pointer& operator/=(std::size_t array_idx)
    {
        return *this /= detail::to_string<string_t>(array_idx);
    }

    /// @brief create a new JSON pointer by appending the right JSON pointer at the end of the left JSON pointer
    /// @sa https://json.nlohmann.me/api/json_pointer/operator_slash/
    friend json_pointer operator/(const json_pointer& lhs,
                                  const json_pointer& rhs)
    {
        json_pointer result;
        result.reference_tokens.reserve(lhs.reference_tokens.size() + rhs.reference_tokens.size());
        result.reference_tokens.insert(result.reference_tokens.end(), lhs.reference_tokens.begin(), lhs.reference_tokens.end());
        result.reference_tokens.insert(result.reference_tokens.end(), rhs.reference_tokens.begin(), rhs.reference_tokens.end());
        return result;
    }

    /// @brief create a new JSON pointer by appending the unescaped token at the end of the JSON pointer
    /// @sa https://json.nlohmann.me/api/json_pointer/operator_slash/
    friend json_pointer operator/(const json_pointer& lhs, string_t token) // NOLINT(performance-unnecessary-value-param)
    {
        json_pointer result;
        result.reference_tokens.reserve(lhs.reference_tokens.size() + 1);
        result.reference_tokens.insert(result.reference_tokens.end(), lhs.reference_tokens.begin(), lhs.reference_tokens.end());
        result.reference_tokens.push_back(std::move(token));
        return result;
    }

    /// @brief create a new JSON pointer by appending the array-index-token at the end of the JSON pointer
    /// @sa https://json.nlohmann.me/api/json_pointer/operator_slash/
    friend json_pointer operator/(const json_pointer& lhs, std::size_t array_idx)
    {
        return lhs / detail::to_string<string_t>(array_idx);
    }

    /// @brief returns the parent of this JSON pointer
    /// @sa https://json.nlohmann.me/api/json_pointer/parent_pointer/
    json_pointer parent_pointer() const
    {
        if (empty())
        {
            return *this;
        }

        json_pointer res;
        res.reference_tokens = std::vector<string_t>(reference_tokens.begin(), reference_tokens.end() - 1);
        return res;
    }

    /// @brief remove first reference token
    /// @sa https://json.nlohmann.me/api/json_pointer/pop_front/
    void pop_front()
    {
        if (JSON_HEDLEY_UNLIKELY(empty()))
        {
            throw_no_parent();
        }

        reference_tokens.erase(reference_tokens.begin());
    }

    /// @brief return first reference token
    /// @sa https://json.nlohmann.me/api/json_pointer/front/
    const string_t& front() const
    {
        if (JSON_HEDLEY_UNLIKELY(empty()))
        {
            throw_no_parent();
        }

        return reference_tokens.front();
    }

    /// @brief append an unescaped token at the start of the reference pointer
    /// @sa https://json.nlohmann.me/api/json_pointer/push_front/
    void push_front(const string_t& token)
    {
        reference_tokens.insert(reference_tokens.begin(), token);
    }

    /// @brief append an unescaped token at the start of the reference pointer
    /// @sa https://json.nlohmann.me/api/json_pointer/push_front/
    void push_front(string_t&& token)
    {
        reference_tokens.insert(reference_tokens.begin(), std::move(token));
    }

    /// @brief remove last reference token
    /// @sa https://json.nlohmann.me/api/json_pointer/pop_back/
    void pop_back()
    {
        if (JSON_HEDLEY_UNLIKELY(empty()))
        {
            throw_no_parent();
        }

        reference_tokens.pop_back();
    }

    /// @brief return last reference token
    /// @sa https://json.nlohmann.me/api/json_pointer/back/
    const string_t& back() const
    {
        if (JSON_HEDLEY_UNLIKELY(empty()))
        {
            throw_no_parent();
        }

        return reference_tokens.back();
    }

    /// @brief append an unescaped token at the end of the reference pointer
    /// @sa https://json.nlohmann.me/api/json_pointer/push_back/
    void push_back(const string_t& token)
    {
        reference_tokens.push_back(token);
    }

    /// @brief append an unescaped token at the end of the reference pointer
    /// @sa https://json.nlohmann.me/api/json_pointer/push_back/
    void push_back(string_t&& token)
    {
        reference_tokens.push_back(std::move(token));
    }

    /// @brief return whether pointer points to the root document
    /// @sa https://json.nlohmann.me/api/json_pointer/empty/
    bool empty() const noexcept
    {
        return reference_tokens.empty();
    }

  private:
    /// @throw out_of_range.405 always
    JSON_HEDLEY_NO_RETURN JSON_HEDLEY_NEVER_INLINE static void throw_no_parent()
    {
        JSON_THROW(detail::out_of_range::create(detail::exception_id::patch_on_root, "JSON pointer has no parent", nullptr));
    }

    /// whether the '~' at @a pos of @a s is not followed by '0' or '1'
    JSON_HEDLEY_ALWAYS_INLINE static bool is_invalid_escape(const string_t& s, std::size_t pos)
    {
        return pos == s.size() - 1 || (s[pos + 1] != '0' && s[pos + 1] != '1');
    }

    /// @throw parse_error.107 always
    JSON_HEDLEY_NO_RETURN JSON_HEDLEY_NEVER_INLINE static void throw_missing_slash(const string_t& pointer)
    {
        static_cast<void>(pointer); // unused when JSON_NOEXCEPTION is defined
        JSON_THROW(detail::parse_error::create(detail::exception_id::pointer_missing_slash, 1, detail::concat("JSON pointer must be empty or begin with '/' - was: '", pointer, "'"), nullptr));
    }

    /// @throw parse_error.107 if a nonempty @a pointer does not begin with '/'
    JSON_HEDLEY_ALWAYS_INLINE static void check_begins_with_slash(const string_t& pointer)
    {
        if (JSON_HEDLEY_UNLIKELY(pointer[0] != '/'))
        {
            throw_missing_slash(pointer);
        }
    }

    /// @throw out_of_range.404 always
    template<typename BasicJsonContext>
    JSON_HEDLEY_NO_RETURN JSON_HEDLEY_NEVER_INLINE static void throw_unresolved(const string_t& reference_token, BasicJsonContext context)
    {
        static_cast<void>(reference_token); // unused when JSON_NOEXCEPTION is defined
        static_cast<void>(context);
        JSON_THROW(detail::out_of_range::create(detail::exception_id::pointer_unresolved, detail::concat("unresolved reference token '", reference_token, "'"), context));
    }

    using array_index_status = detail::array_index_status;

    /// whether a reference token is "-" (a plain comparison with a string literal is not always inlined)
    static bool is_dash(const string_t& s) noexcept
    {
        return s.size() == 1 && s[0] == '-';
    }

    /// detail::parse_array_index() for the size_type of @a BasicJsonType
    template<typename BasicJsonType>
    static array_index_status parse_array_index(const string_t& s, typename BasicJsonType::size_type& idx) noexcept
    {
        return detail::parse_array_index(s, idx);
    }

    /*!
    @param[in] s  reference token to be converted into an array index

    @return integer representation of @a s

    @throw parse_error.106  if an array index begins with '0'
    @throw parse_error.109  if an array index begins not with a digit
    @throw out_of_range.404 if string @a s could not be converted to an integer
    @throw out_of_range.410 if an array index exceeds size_type
    */
    template<typename BasicJsonType>
    static typename BasicJsonType::size_type array_index(const string_t& s)
    {
        typename BasicJsonType::size_type idx{};
        switch (parse_array_index<BasicJsonType>(s, idx))
        {
            // the branches differ in their messages, not after JSON_THROW's expansion
            // NOLINTNEXTLINE(bugprone-branch-clone)
            case array_index_status::leading_zero:
                JSON_THROW(detail::parse_error::create(detail::exception_id::pointer_index_leading_zero, 0, detail::concat("array index '", s, "' must not begin with '0'"), nullptr));
            case array_index_status::not_a_number:
                JSON_THROW(detail::parse_error::create(detail::exception_id::pointer_index_not_a_number, 0, detail::concat("array index '", s, "' is not a number"), nullptr));
            case array_index_status::unresolved:
                throw_unresolved(s, nullptr);
            case array_index_status::exceeds_size_type:
                JSON_THROW(detail::out_of_range::create(detail::exception_id::value_out_of_range, detail::concat("array index ", s, " exceeds size_type"), nullptr));
            case array_index_status::ok:
            default:
                break;
        }

        return idx;
    }

    /*!
    @brief compare with a JSON pointer string without splitting it into tokens

    @throw parse_error.107  if the string is not empty or begins with '/'
    @throw parse_error.108  if character '~' is not followed by '0' or '1'
    */
    bool equals_string(const string_t& reference_string) const
    {
        if (reference_string.empty())
        {
            return reference_tokens.empty();
        }

        check_begins_with_slash(reference_string);

        // the whole string is validated, whether or not it matches
        const std::size_t size = reference_string.size();
        for (std::size_t pos = reference_string.find_first_of('~');
                pos != string_t::npos;
                pos = reference_string.find_first_of('~', pos + 1))
        {
            if (JSON_HEDLEY_UNLIKELY(is_invalid_escape(reference_string, pos)))
            {
                JSON_THROW(detail::parse_error::create(detail::exception_id::pointer_invalid_escape, 0, "escape character '~' must be followed with '0' or '1'", nullptr));
            }
        }

        // compare token by token, unescaping the string on the fly
        std::size_t pos = 0; // the slash in front of the next token
        for (const auto& reference_token : reference_tokens)
        {
            if (pos >= size)
            {
                return false;
            }

            std::size_t i = pos + 1;
            std::size_t j = 0;
            const std::size_t token_size = reference_token.size();
            while (i < size && reference_string[i] != '/')
            {
                char c = reference_string[i++];
                if (c == '~')
                {
                    c = (reference_string[i++] == '0') ? '~' : '/';
                }
                if (j == token_size || reference_token[j] != c)
                {
                    return false;
                }
                ++j;
            }
            if (j != token_size)
            {
                return false;
            }
            pos = i;
        }
        return pos == size;
    }

    /// reserve room for @a n elements of an array type that has reserve()
    template<typename ArrayType>
    static auto reserve_elements(ArrayType& array, const std::size_t n, detail::priority_tag<1> /*unused*/)
    -> decltype(array.reserve(n), void())
    {
        array.reserve(n);
    }

    template<typename ArrayType>
    static void reserve_elements(ArrayType& /*array*/, const std::size_t /*n*/, detail::priority_tag<0> /*unused*/)
    {}

    /// @brief object member access with a key that is only copied if it is inserted
    ///
    /// Objects that can find the position of a key and insert there
    /// (std::map) search once, others look the key up and add it if it is missing.
    template<typename BasicJsonType>
    static auto object_member_impl(BasicJsonType& object, const string_t& key, detail::priority_tag<1> /*unused*/)
    -> decltype(object.m_data.m_value.object->emplace_hint(object.m_data.m_value.object->lower_bound(key), key, nullptr), std::declval<BasicJsonType&>())
    {
        auto& members = *object.m_data.m_value.object;
        auto it = members.lower_bound(key);
        if (it != members.end() && !members.key_comp()(key, it->first))
        {
            return it->second;
        }

        const auto old_capacity = object.container_capacity();
        it = members.emplace_hint(it, key, nullptr);
        return object.set_parent_after_insert(it->second, old_capacity);
    }

    template<typename BasicJsonType>
    static BasicJsonType& object_member_impl(BasicJsonType& object, const string_t& key, detail::priority_tag<0> /*unused*/)
    {
        auto& members = *object.m_data.m_value.object;
        const auto it = members.find(key);
        if (it != members.end())
        {
            return it->second;
        }
        return object.operator[](key);
    }

    template<typename BasicJsonType>
    static BasicJsonType& object_member(BasicJsonType& object, const string_t& key)
    {
        return object_member_impl(object, key, detail::priority_tag<1> {});
    }

  JSON_PRIVATE_UNLESS_TESTED:
    json_pointer top() const
    {
        if (JSON_HEDLEY_UNLIKELY(empty()))
        {
            throw_no_parent();
        }

        json_pointer result = *this;
        result.reference_tokens = {reference_tokens[0]};
        return result;
    }

  private:
    /*!
    @brief the pointer prefixes of a flattened object that denote arrays

    @ref unflatten creates arrays exactly below the prefixes that have a
    reference token 0 among their children, and objects everywhere else.
    Deciding this up front keeps the result independent of the order in which
    the flattened object is iterated, which is unspecified for some object
    types.

    A prefix is identified by the text of the key it is the beginning of:
    escaping is unambiguous, so equal prefixes of valid keys are equal texts.
    The set refers to the keys, which must outlive it.
    */
    class array_prefix_set
    {
      public:
        void insert(const char* data, std::size_t size)
        {
            // flattened objects are usually sorted, so most keys that have a
            // 0 yield the prefix of the previous one
            if (last_data != nullptr && last_size == size && std::memcmp(last_data, data, size) == 0)
            {
                return;
            }
            last_data = data;
            last_size = size;

            if (table.empty())
            {
                table.resize(16);
            }
            const std::size_t hash = hash_of(data, size);
            const std::size_t mask = table.size() - 1;
            std::size_t i = hash & mask;
            while (table[i].data != nullptr)
            {
                if (table[i].hash == hash && table[i].size == size && std::memcmp(table[i].data, data, size) == 0)
                {
                    return;
                }
                i = (i + 1) & mask;
            }
            table[i] = slot(hash, data, size);

            // keep the load factor below 1/2
            if (++used * 2 > table.size())
            {
                grow();
            }
        }

        bool empty() const noexcept
        {
            return used == 0;
        }

        bool contains(const char* data, std::size_t size) const noexcept
        {
            if (used == 0)
            {
                return false;
            }
            const std::size_t hash = hash_of(data, size);
            const std::size_t mask = table.size() - 1;
            for (std::size_t i = hash & mask; table[i].data != nullptr; i = (i + 1) & mask)
            {
                if (table[i].hash == hash && table[i].size == size && std::memcmp(table[i].data, data, size) == 0)
                {
                    return true;
                }
            }
            return false;
        }

      private:
        struct slot
        {
            slot() noexcept = default;

            slot(std::size_t h, const char* d, std::size_t s) noexcept
                : hash(h), data(d), size(s)
            {}

            std::size_t hash = 0;
            const char* data = nullptr; // nullptr: the slot is empty
            std::size_t size = 0;
        };

        static std::size_t hash_of(const char* data, std::size_t size) noexcept
        {
            std::uint64_t h = 0x9E3779B97F4A7C15ULL ^ size;
            std::size_t i = 0;
            for (; i + 8 <= size; i += 8)
            {
                std::uint64_t w = 0;
                std::memcpy(&w, data + i, 8);
                h = (h ^ w) * 0x100000001B3ULL;
                h ^= h >> 32u;
            }
            std::uint64_t w = 0;
            if (i < size)
            {
                std::memcpy(&w, data + i, size - i);
            }
            h = (h ^ w) * 0x9E3779B97F4A7C15ULL;
            return detail::conditional_static_cast<std::size_t>(h ^ (h >> 29u));
        }

        void grow()
        {
            std::vector<slot> old(table.size() * 2);
            old.swap(table);
            const std::size_t mask = table.size() - 1;
            for (const auto& s : old)
            {
                if (s.data != nullptr)
                {
                    std::size_t i = s.hash & mask;
                    while (table[i].data != nullptr)
                    {
                        i = (i + 1) & mask;
                    }
                    table[i] = s;
                }
            }
        }

        std::vector<slot> table{};
        std::size_t used = 0;
        const char* last_data = nullptr;
        std::size_t last_size = 0;
    };

    /// @brief the length of the longest common prefix of the first @a limit bytes of @a a and @a b
    static std::size_t common_prefix_length(const char* a, const char* b, const std::size_t limit) noexcept
    {
        std::size_t i = 0;
        for (; i + 8 <= limit; i += 8)
        {
            std::uint64_t x = 0;
            std::uint64_t y = 0;
            std::memcpy(&x, a + i, 8);
            std::memcpy(&y, b + i, 8);
            if (x != y)
            {
                break;
            }
        }
        while (i < limit && a[i] == b[i])
        {
            ++i;
        }
        return i;
    }

    /*!
    @brief check that @a key is a valid JSON pointer, and add the prefixes of
           it that denote arrays to @a arrays

    @throw parse_error.107  if the key is not empty or begins with '/'
    @throw parse_error.108  if character '~' is not followed by '0' or '1'

    The same checks as @ref split, which throws the same exceptions, but
    without building the reference tokens.
    */
    static void scan_key(const string_t& key, const string_t* previous, array_prefix_set& arrays)
    {
        const std::size_t size = key.size();
        if (size == 0)
        {
            return;
        }

        const char* const data = key.data();
        check_begins_with_slash(key);

        // The beginning of the key that it has in common with the previous
        // one, which was checked already, is skipped: the scan starts with
        // the token after the last slash in it.
        std::size_t begin = 1;
        if (previous != nullptr)
        {
            std::size_t same = common_prefix_length(data, previous->data(), (std::min)(size, previous->size()));
            while (same > 1 && data[same - 1] != '/')
            {
                --same;
            }
            if (same > 1)
            {
                begin = same;
            }
        }

        for (std::size_t i = begin; i <= size; ++i)
        {
            if (i == size || data[i] == '/')
            {
                // a token 0 makes the pointer before it an array
                if (i - begin == 1 && data[begin] == '0')
                {
                    arrays.insert(data, begin - 1);
                }
                begin = i + 1;
            }
            else if (data[i] == '~')
            {
                // ~ must be followed by 0 or 1
                if (JSON_HEDLEY_UNLIKELY(is_invalid_escape(key, i)))
                {
                    JSON_THROW(detail::parse_error::create(detail::exception_id::pointer_invalid_escape, 0, "escape character '~' must be followed with '0' or '1'", nullptr));
                }
            }
        }
    }

    /*!
    @brief the values along the pointer last resolved by @ref resolve_plain

    A patch from @ref basic_json::diff lists its operations in document order,
    so consecutive pointers share most of their reference tokens; the values
    along the previous pointer are kept to resume from the common prefix.
    `steps[k]` is the value after the first `k` reference tokens together with
    the length of the prefix of `*path` that holds them. A value stays valid as
    long as no operation changes its container: callers keep only values up to
    the parent of the pointer they modify, or call `reset()`.
    */
    template<typename BasicJsonType>
    struct plain_steps
    {
        const string_t* path = nullptr;
        std::vector<std::pair<std::size_t, BasicJsonType*>> steps{};

        void reset() noexcept
        {
            path = nullptr;
            steps.clear();
        }
    };

    /*!
    @brief resolve a plain JSON pointer without building its reference tokens

    @param[in] root    the value the pointer starts at
    @param[in] path    a JSON pointer string
    @param[in] length  the number of leading bytes of @a path to resolve; 0 or
                       the position of a slash
    @param[in,out] token  a string to hold the reference tokens, to reuse its storage
    @param[in,out] cache  the values along the previously resolved pointer;
                          @a path must outlive the next call

    @return the pointed to value, or `nullptr` if the pointer does not denote
            an existing value, or does so in a way that is not plain: an array
            index that is malformed or out of range, or a "-", or a reference
            token with an escape. No exception is
            thrown for these; callers use @ref json_pointer instead, which
            handles them.
    */
    template<typename BasicJsonType>
    static BasicJsonType* resolve_plain(BasicJsonType* root, const string_t& path, const std::size_t length, string_t& token, plain_steps<BasicJsonType>& cache)
    {
        auto& steps = cache.steps;

        // resume from the deepest step that is also a prefix of this path
        std::size_t depth = 1;
        if (cache.path != nullptr && !steps.empty() && steps[0].second == root)
        {
            const string_t& previous = *cache.path;
            for (depth = steps.size(); depth > 1; --depth)
            {
                // a step ends at a token boundary of the previous path
                const std::size_t prefix = steps[depth - 1].first;
                if (prefix <= length && (prefix == length || path[prefix] == '/') && std::memcmp(path.data(), previous.data(), prefix) == 0)
                {
                    break;
                }
            }
            steps.resize(depth);
        }
        else
        {
            steps.assign(1, std::make_pair(std::size_t{0}, root));
        }
        cache.path = &path;

        BasicJsonType* ptr = steps[depth - 1].second;
        for (std::size_t pos = steps[depth - 1].first; pos < length;)
        {
            if (JSON_HEDLEY_UNLIKELY(path[pos] != '/'))
            {
                return nullptr;
            }

            // the reference token between the slash at pos and the next one,
            // which must not have an escape
            const char* const begin = path.data() + pos + 1;
            const char* const limit = path.data() + length;
            const char* end = begin;
            while (end < limit && *end != '/')
            {
                if (JSON_HEDLEY_UNLIKELY(*end == '~'))
                {
                    return nullptr;
                }
                ++end;
            }

            if (ptr->is_object())
            {
                token.clear();
                token.append(begin, static_cast<std::size_t>(end - begin));
                const auto it = ptr->m_data.m_value.object->find(token);
                if (JSON_HEDLEY_UNLIKELY(it == ptr->m_data.m_value.object->end()))
                {
                    return nullptr;
                }
                ptr = &it->second;
            }
            else if (ptr->is_array())
            {
                // an index of up to 18 digits without a leading zero fits into size_type
                // (9 digits for a 32-bit size_type); everything else is left to json_pointer
                constexpr std::size_t max_digits = sizeof(typename BasicJsonType::size_type) >= 8 ? 18 : 9;
                const auto digits = static_cast<std::size_t>(end - begin);
                if (JSON_HEDLEY_UNLIKELY(digits == 0 || digits > max_digits || (digits > 1 && *begin == '0')))
                {
                    return nullptr;
                }
                typename BasicJsonType::size_type idx = 0;
                for (const char* c = begin; c != end; ++c)
                {
                    if (JSON_HEDLEY_UNLIKELY(*c < '0' || *c > '9'))
                    {
                        return nullptr;
                    }
                    idx = static_cast<typename BasicJsonType::size_type>((idx * 10) + static_cast<typename BasicJsonType::size_type>(*c - '0'));
                }
                if (JSON_HEDLEY_UNLIKELY(idx >= ptr->m_data.m_value.array->size()))
                {
                    return nullptr;
                }
                ptr = &(*ptr->m_data.m_value.array)[idx];
            }
            else
            {
                // primitive value with a reference token left
                return nullptr;
            }
            pos = static_cast<std::size_t>(end - path.data());
            steps.emplace_back(pos, ptr);
        }

        return ptr;
    }

    /*!
    @brief return a reference to the pointed to value

    @note This version does not throw if a value is not present, but tries to
          create nested values instead. For instance, calling this function
          with pointer `"/this/that"` on a null value is equivalent to calling
          `operator[]("this").operator[]("that")` on that value, effectively
          changing the null value to an object.

    @param[in] ptr  a JSON value

    @return reference to the JSON value pointed to by the JSON pointer

    Complexity: Linear in the length of the JSON pointer.

    @throw parse_error.106   if an array index begins with '0'
    @throw parse_error.109   if an array index was not a number
    @throw out_of_range.404  if the JSON pointer can not be resolved
    */
    template<typename BasicJsonType>
    BasicJsonType& get_unchecked(BasicJsonType* ptr) const
    {
        for (const auto& reference_token : reference_tokens)
        {
            // convert null values to arrays or objects before continuing
            if (ptr->is_null())
            {
                // check if the reference token is a number
                const bool nums =
                    std::all_of(reference_token.begin(), reference_token.end(),
                                [](const unsigned char x)
                {
                    return std::isdigit(x);
                });

                // change value to an array for numbers or "-" or to object otherwise
                *ptr = (nums || reference_token == "-")
                       ? detail::value_t::array
                       : detail::value_t::object;
            }

            if (ptr->is_object())
            {
                // use unchecked object access
                ptr = &object_member(*ptr, reference_token);
            }
            else if (ptr->is_array())
            {
                if (reference_token == "-")
                {
                    // explicitly treat "-" as index beyond the end
                    ptr = &ptr->operator[](ptr->m_data.m_value.array->size());
                }
                else
                {
                    // convert array index to number; unchecked access
                    ptr = &ptr->operator[](array_index<BasicJsonType>(reference_token));
                }
            }
            else
            {
                // primitive value with a reference token left
                throw_unresolved(reference_token, ptr);
            }
        }

        return *ptr;
    }

    /*!
    @throw parse_error.106   if an array index begins with '0'
    @throw parse_error.109   if an array index was not a number
    @throw out_of_range.402  if the array index '-' is used
    @throw out_of_range.404  if the JSON pointer can not be resolved
    */
    template<typename BasicJsonType>
    BasicJsonType& get_checked(BasicJsonType* ptr) const
    {
        for (const auto& reference_token : reference_tokens)
        {
            if (ptr->is_object())
            {
                const auto it = ptr->m_data.m_value.object->find(reference_token);
                if (JSON_HEDLEY_UNLIKELY(it == ptr->m_data.m_value.object->end()))
                {
                    // at() throws out_of_range.403 with the usual message
                    ptr->at(reference_token);
                }
                ptr = &it->second;
            }
            else if (ptr->is_array())
            {
                if (JSON_HEDLEY_UNLIKELY(is_dash(reference_token)))
                {
                    // "-" always fails the range check
                    JSON_THROW(detail::out_of_range::create(detail::exception_id::pointer_past_the_end_index, detail::concat(
                            "array index '-' (", std::to_string(ptr->m_data.m_value.array->size()),
                            ") is out of range"), ptr));
                }

                const auto idx = array_index<BasicJsonType>(reference_token);
                // Bounds check before access to avoid exception with JSON_NOEXCEPTION
                if (JSON_HEDLEY_UNLIKELY(idx >= ptr->m_data.m_value.array->size()))
                {
                    JSON_THROW(detail::out_of_range::create(detail::exception_id::array_index_out_of_range, detail::concat(
                            "array index ", std::to_string(idx), " is out of range"), ptr));
                }
                ptr = &(*ptr->m_data.m_value.array)[idx];
            }
            else
            {
                // primitive value with a reference token left
                throw_unresolved(reference_token, ptr);
            }
        }

        return *ptr;
    }

    /*!
    @brief return a const reference to the pointed to value

    @param[in] ptr  a JSON value

    @return const reference to the JSON value pointed to by the JSON
    pointer

    @pre Every object key and array index the pointer refers to exists.
         Like the const operator[] for keys and indices, a missing one is
         undefined behavior, guarded by a runtime assertion.

    @throw parse_error.106   if an array index begins with '0'
    @throw parse_error.109   if an array index was not a number
    @throw out_of_range.402  if the array index '-' is used
    @throw out_of_range.404  if the JSON pointer can not be resolved
    */
    template<typename BasicJsonType>
    const BasicJsonType& get_unchecked(const BasicJsonType* ptr) const
    {
        for (const auto& reference_token : reference_tokens)
        {
            if (ptr->is_object())
            {
                // use unchecked object access; the const operator[]
                // asserts that the key exists
                const auto it = ptr->m_data.m_value.object->find(reference_token);
                JSON_ASSERT(it != ptr->m_data.m_value.object->end());
                ptr = &it->second;
            }
            else if (ptr->is_array())
            {
                if (JSON_HEDLEY_UNLIKELY(is_dash(reference_token)))
                {
                    // "-" cannot be used for const access
                    JSON_THROW(detail::out_of_range::create(detail::exception_id::pointer_past_the_end_index, detail::concat("array index '-' (", std::to_string(ptr->m_data.m_value.array->size()), ") is out of range"), ptr));
                }

                // use unchecked array access; the const operator[]
                // asserts that the index exists
                const auto idx = array_index<BasicJsonType>(reference_token);
                JSON_ASSERT(idx < ptr->m_data.m_value.array->size());
                ptr = &(*ptr->m_data.m_value.array)[idx];
            }
            else
            {
                // primitive value with a reference token left
                throw_unresolved(reference_token, ptr);
            }
        }

        return *ptr;
    }

    /*!
    @brief return a pointer to the pointed to value, or `nullptr` if the
           pointer cannot be resolved because a key is missing, an array
           index is out of range, or the array index is "-"

    @note unlike get_checked(), this never throws for those cases, so it
          can be used to implement a non-throwing fallback (e.g. value())
          that also works when exceptions are disabled

    @throw parse_error.106   if an array index begins with '0'
    @throw parse_error.109   if an array index was not a number
    */
    template<typename BasicJsonType>
    const BasicJsonType* get_checked_or_null(const BasicJsonType* ptr) const
    {
        for (const auto& reference_token : reference_tokens)
        {
            if (ptr->is_object())
            {
                const auto it = ptr->m_data.m_value.object->find(reference_token);
                if (JSON_HEDLEY_UNLIKELY(it == ptr->m_data.m_value.object->end()))
                {
                    return nullptr;
                }
                ptr = &it->second;
            }
            else if (ptr->is_array())
            {
                if (JSON_HEDLEY_UNLIKELY(is_dash(reference_token)))
                {
                    // "-" always fails the range check
                    return nullptr;
                }

                // a malformed index throws parse_error.106/109; an
                // index that is syntactically valid but cannot be
                // represented (out_of_range.404/410) is treated like an
                // out-of-range index below
                typename BasicJsonType::size_type idx{};
                switch (parse_array_index<BasicJsonType>(reference_token, idx))
                {
                    // the branches differ in their messages, not after JSON_THROW's expansion
                    // NOLINTNEXTLINE(bugprone-branch-clone)
                    case array_index_status::leading_zero:
                        JSON_THROW(detail::parse_error::create(detail::exception_id::pointer_index_leading_zero, 0, detail::concat("array index '", reference_token, "' must not begin with '0'"), nullptr));
                    case array_index_status::not_a_number:
                        JSON_THROW(detail::parse_error::create(detail::exception_id::pointer_index_not_a_number, 0, detail::concat("array index '", reference_token, "' is not a number"), nullptr));
                    case array_index_status::unresolved:
                    case array_index_status::exceeds_size_type:
                        return nullptr;
                    case array_index_status::ok:
                    default:
                        break;
                }

                if (JSON_HEDLEY_UNLIKELY(idx >= ptr->m_data.m_value.array->size()))
                {
                    return nullptr;
                }
                ptr = &(*ptr->m_data.m_value.array)[idx];
            }
            else
            {
                // primitive value with a reference token left
                return nullptr;
            }
        }

        return ptr;
    }

    /*!
    @note unlike array_index(), this never throws: a malformed or unrepresentable
          array index reference token is treated like a missing key (see #5395)
    */
    template<typename BasicJsonType>
    bool contains(const BasicJsonType* ptr) const
    {
        for (const auto& reference_token : reference_tokens)
        {
            if (ptr->is_object())
            {
                const auto it = ptr->m_data.m_value.object->find(reference_token);
                if (it == ptr->m_data.m_value.object->end())
                {
                    // we did not find the key in the object
                    return false;
                }

                ptr = &it->second;
            }
            else if (ptr->is_array())
            {
                if (JSON_HEDLEY_UNLIKELY(is_dash(reference_token)))
                {
                    // "-" always fails the range check
                    return false;
                }

                // any parse failure (malformed index, or one that is syntactically
                // valid but not representable as size_type) means the reference
                // token cannot denote an existing array element -- contains() must
                // not throw (see #5395), so it is treated as "not found"
                typename BasicJsonType::size_type idx{};
                if (JSON_HEDLEY_UNLIKELY(parse_array_index<BasicJsonType>(reference_token, idx) != array_index_status::ok))
                {
                    return false;
                }

                if (idx >= ptr->m_data.m_value.array->size())
                {
                    // index out of range
                    return false;
                }

                ptr = &(*ptr->m_data.m_value.array)[idx];
            }
            else
            {
                // we do not expect primitive values if there is still a
                // reference token to process
                return false;
            }
        }

        // no reference token left means we found a primitive value
        return true;
    }

    /*!
    @brief split the string input to reference tokens

    @note This function is only called by the json_pointer constructor.
          All exceptions below are documented there.

    @throw parse_error.107  if the pointer is not empty or begins with '/'
    @throw parse_error.108  if character '~' is not followed by '0' or '1'
    */
    static std::vector<string_t> split(const string_t& reference_string)
    {
        std::vector<string_t> result;

        // special case: empty reference string -> no reference tokens
        if (reference_string.empty())
        {
            return result;
        }

        // check if a nonempty reference string begins with slash
        check_begins_with_slash(reference_string);

        // every slash starts a reference token
        const std::size_t size = reference_string.size();
        std::size_t token_count = 0;
        for (std::size_t i = 0; i < size; ++i)
        {
            token_count += static_cast<std::size_t>(reference_string[i] == '/');
        }
        result.reserve(token_count);

        // extract the reference tokens: every one runs from after a slash to
        // the next slash or the end of the string; a token without a '~' (the
        // common case) is stored as it is, others are checked and unescaped
        const char* const data = reference_string.data();
        const char* const end = data + size;
        for (const char* start = data + 1;; ++start)
        {
            const char* slash = start;
            bool escaped = false;
            while (slash != end && *slash != '/')
            {
                escaped = escaped || *slash == '~';
                ++slash;
            }

            const auto count = static_cast<std::size_t>(slash - start);
            if (JSON_HEDLEY_LIKELY(!escaped))
            {
                result.emplace_back(start, count);
            }
            else
            {
                auto reference_token = string_t(start, count);

                // check reference tokens are properly escaped
                for (std::size_t pos = reference_token.find_first_of('~'); pos != string_t::npos; pos = reference_token.find_first_of('~', pos + 1))
                {
                    JSON_ASSERT(reference_token[pos] == '~');

                    // ~ must be followed by 0 or 1
                    if (JSON_HEDLEY_UNLIKELY(is_invalid_escape(reference_token, pos)))
                    {
                        JSON_THROW(detail::parse_error::create(detail::exception_id::pointer_invalid_escape, 0, "escape character '~' must be followed with '0' or '1'", nullptr));
                    }
                }

                detail::unescape(reference_token);
                result.push_back(std::move(reference_token));
            }

            if (slash == end)
            {
                break;
            }
            start = slash;
        }

        return result;
    }

  private:
    // Add the entry (key, v) to the object `obj`. Flattened paths are pairwise
    // distinct, so objects that can append a key known to be absent
    // (ordered_map) skip the lookup, which is linear and would make flatten
    // quadratic. Objects with a positional insert (std::map) insert next to
    // the entry added last: paths come out in nearly sorted order, so the
    // position is usually right and no search from the root is needed.
    // All other object types use operator[].
    template<typename ObjectType, typename ValueType>
    static auto add_flattened(ObjectType& obj, typename ObjectType::iterator& /*hint*/, const string_t& key, ValueType&& v, detail::priority_tag<2> /*unused*/)
    -> decltype(obj.emplace_new_key(key, std::forward<ValueType>(v)), void())
    {
        obj.emplace_new_key(key, std::forward<ValueType>(v));
    }

    template<typename ObjectType, typename ValueType>
    static auto add_flattened(ObjectType& obj, typename ObjectType::iterator& hint, const string_t& key, ValueType&& v, detail::priority_tag<1> /*unused*/)
    -> decltype(hint = obj.emplace_hint(hint, key, std::forward<ValueType>(v)), void())
    {
        hint = obj.emplace_hint(hint, key, std::forward<ValueType>(v));
        ++hint;
    }

    template<typename ObjectType, typename ValueType>
    static void add_flattened(ObjectType& obj, typename ObjectType::iterator& /*hint*/, const string_t& key, ValueType&& v, detail::priority_tag<0> /*unused*/)
    {
        obj[key] = std::forward<ValueType>(v);
    }

    /// the number of entries that flattening @a value adds: its primitive
    /// values and empty containers
    template<typename BasicJsonType>
    static std::size_t count_flattened(const BasicJsonType& value)
    {
        std::size_t count = 0;
        std::vector<const BasicJsonType*> pending(1, &value);
        while (!pending.empty())
        {
            const BasicJsonType* const v = pending.back();
            pending.pop_back();
            if (v->is_array() && !v->m_data.m_value.array->empty())
            {
                for (const auto& element : *v->m_data.m_value.array)
                {
                    pending.push_back(&element);
                }
            }
            else if (v->is_object() && !v->m_data.m_value.object->empty())
            {
                for (const auto& member : *v->m_data.m_value.object)
                {
                    pending.push_back(&member.second);
                }
            }
            else
            {
                ++count;
            }
        }
        return count;
    }

    // Reserve the storage for @a value of objects that have a reserve(), so
    // that it does not have to be moved while it grows
    template<typename ObjectType, typename BasicJsonType>
    static auto reserve_flattened(ObjectType& obj, const BasicJsonType& value, detail::priority_tag<1> /*unused*/)
    -> decltype(obj.reserve(std::size_t {}), void())
    {
        obj.reserve(count_flattened(value));
    }

    template<typename ObjectType, typename BasicJsonType>
    static void reserve_flattened(ObjectType& /*obj*/, const BasicJsonType& /*value*/, detail::priority_tag<0> /*unused*/)
    {}

    /// append the decimal representation of @a i to @a out
    static void append_index(string_t& out, std::size_t i)
    {
        std::array<char, 24> buf{};
        std::size_t pos = buf.size();
        do
        {
            buf[--pos] = static_cast<char>('0' + (i % 10));
            i /= 10;
        }
        while (i != 0);
        out.append(buf.data() + pos, buf.size() - pos);
    }

    /*!
    @param[in] reference_string  the reference string to the current value
    @param[in] value             the value to consider
    @param[in,out] result        the result object to insert values to

    @note Empty objects or arrays are flattened to `null`.

    The value is walked with an explicit stack rather than the call stack, so
    arbitrarily deeply nested values can be flattened.

    @sa https://github.com/nlohmann/json/issues/5393
    */
    template<typename BasicJsonType>
    static void flatten(const string_t& reference_string,
                        const BasicJsonType& value,
                        BasicJsonType& result)
    {
        using object_const_iterator = typename BasicJsonType::object_t::const_iterator;

        // an array or object being walked: the container, the array index or
        // object iterator of the next child, and the length of the path of the
        // container itself
        struct frame
        {
            frame(const BasicJsonType* container_, object_const_iterator member_, const std::size_t path_length_) noexcept
                : container(container_), member(std::move(member_)), path_length(path_length_)
            {}

            const BasicJsonType* container;
            std::size_t index = 0;
            object_const_iterator member;
            std::size_t path_length;
        };

        // The containers being flattened are kept on an explicit stack, and
        // every child is flattened completely before the next one, so the
        // entries come out in the same order as with a recursive walk. The
        // path of the value being flattened is kept in one buffer that grows
        // and shrinks with the stack, rather than in a new string per level.
        std::vector<frame> stack;
        string_t path = reference_string;

        // flatten `v`, whose path is `path`: primitives and empty containers
        // are added to the result right away; other containers get a frame
        auto& object = *result.m_data.m_value.object;
        auto hint = object.end();
        const auto enter = [&stack, &path, &object, &hint](const BasicJsonType & v)
        {
            if (v.is_array())
            {
                if (v.m_data.m_value.array->empty())
                {
                    // flatten empty array as null
                    add_flattened(object, hint, path, nullptr, detail::priority_tag<2> {});
                }
                else
                {
                    stack.emplace_back(&v, object_const_iterator(), path.size());
                }
            }
            else if (v.is_object())
            {
                if (v.m_data.m_value.object->empty())
                {
                    // flatten empty object as null
                    add_flattened(object, hint, path, nullptr, detail::priority_tag<2> {});
                }
                else
                {
                    stack.emplace_back(&v, v.m_data.m_value.object->begin(), path.size());
                }
            }
            else
            {
                // add a primitive value with its reference string
                add_flattened(object, hint, path, v, detail::priority_tag<2> {});
            }
        };

        reserve_flattened(object, value, detail::priority_tag<1> {});
        enter(value);
        while (!stack.empty())
        {
            // the frame is changed through stack.back(): enter() may push a
            // frame, which would invalidate a reference to it
            const BasicJsonType* const container = stack.back().container;

            // the path of the previous child is replaced by the path of the
            // next one; for an array element in one resize
            const std::size_t path_length = stack.back().path_length;

            if (container->is_array())
            {
                const auto& array = *container->m_data.m_value.array;
                const std::size_t i = stack.back().index;
                if (i == array.size())
                {
                    stack.pop_back();
                    continue;
                }

                // iterate array and use index as a reference string
                ++stack.back().index;
                std::array<char, 24> digits{};
                std::size_t pos = digits.size();
                std::size_t rest = i;
                do
                {
                    digits[--pos] = static_cast<char>('0' + (rest % 10));
                    rest /= 10;
                }
                while (rest != 0);
                const std::size_t count = digits.size() - pos;
                path.resize(path_length + 1 + count);
                char* const out = &path[path_length];
                out[0] = '/';
                std::memcpy(out + 1, digits.data() + pos, count);
                enter(array[i]);
            }
            else
            {
                const object_const_iterator it = stack.back().member;
                if (it == container->m_data.m_value.object->end())
                {
                    stack.pop_back();
                    continue;
                }

                // iterate object and use keys as reference string
                ++stack.back().member;
                path.resize(path_length);
                path.push_back('/');
                detail::escape_into(path, it->first);
                enter(it->second);
            }
        }

        // the entries were added without going through basic_json, so the
        // parent pointers (JSON_DIAGNOSTICS) have to be set now
        result.set_parents();
    }

    /*!
    @param[in] value  flattened JSON

    @return unflattened JSON

    @throw parse_error.109 if array index is not a number
    @throw type_error.314  if value is not an object
    @throw type_error.315  if object values are not primitive
    @throw type_error.313  if value cannot be unflattened
    */
    template<typename BasicJsonType>
    static BasicJsonType
    unflatten(const BasicJsonType& value)
    {
        if (JSON_HEDLEY_UNLIKELY(!value.is_object()))
        {
            JSON_THROW(detail::type_error::create(detail::exception_id::unflatten_not_object, "only objects can be unflattened", &value));
        }

        BasicJsonType result;

        // check every key, and collect the prefixes that have a reference
        // token 0 among their children; the values below them are arrays,
        // all others are objects (see array_prefix_set)
        array_prefix_set arrays;
        const string_t* previous_key = nullptr;
        for (const auto& element : *value.m_data.m_value.object)
        {
            scan_key(element.first, previous_key, arrays);
            previous_key = &element.first;
        }

        // values[i] is the value after the first i reference tokens of the
        // previous key, ends[i] the length of that prefix of the key. Keys are
        // often sorted, so most of the path to the value of a key is the
        // same as for the previous key and need not be looked up again. Only
        // the values below the common prefix are dropped, and only they can
        // move when a value is added: the ones above are not inside the
        // container that grows.
        std::vector<BasicJsonType*> values(1, &result);
        std::vector<std::size_t> ends(1, 0);
        const string_t* previous = nullptr;
        string_t token;

        // iterate the JSON object values
        for (const auto& element : *value.m_data.m_value.object)
        {
            if (JSON_HEDLEY_UNLIKELY(!element.second.is_primitive()))
            {
                JSON_THROW(detail::type_error::create(detail::exception_id::unflatten_value_not_primitive, "values in object must be primitive", &element.second));
            }

            const string_t& key = element.first;
            const char* const data = key.data();

            // the number of reference tokens the key has in common with the
            // previous one
            std::size_t depth = 0;
            if (previous != nullptr)
            {
                const std::size_t same = common_prefix_length(data, previous->data(), (std::min)(key.size(), previous->size()));
                depth = ends.size() - 1;
                while (depth > 0 && (ends[depth] > same || (ends[depth] == same && same < key.size() && data[same] != '/')))
                {
                    --depth;
                }
            }
            values.resize(depth + 1);
            ends.resize(depth + 1);
            previous = &key;

            // Assign the value to the reference pointed to by JSON pointer. Note
            // that if the JSON pointer is "" (i.e., points to the whole value),
            // the value is the result itself. An assignment will then create a
            // primitive value.
            BasicJsonType* current = values.back();
            for (std::size_t pos = ends.back(); pos < key.size();)
            {
                // the reference token between the slash at pos and the next
                std::size_t end = key.find_first_of('/', pos + 1);
                if (end == string_t::npos)
                {
                    end = key.size();
                }
                const std::size_t token_size = end - pos - 1;

                // a token that is a plain index of up to 9 digits, which is
                // the case for almost all array elements, is not copied
                std::size_t index = 0;
                bool plain_index = current->type() == detail::value_t::array && token_size != 0 && token_size <= 9 && (token_size == 1 || data[pos + 1] != '0');
                for (std::size_t k = pos + 1; plain_index && k < end; ++k)
                {
                    plain_index = data[k] >= '0' && data[k] <= '9';
                    index = (index * 10) + static_cast<std::size_t>(data[k] - '0');
                }
                if (plain_index)
                {
                    current = &current->operator[](static_cast<typename BasicJsonType::size_type>(index));
                    values.push_back(current);
                    ends.push_back(end);
                    pos = end;
                    continue;
                }

                token.clear();
                token.append(data + pos + 1, token_size);
                if (token.find_first_of('~') != string_t::npos)
                {
                    detail::unescape(token);
                }

                switch (current->type())
                {
                    case detail::value_t::null:
                    {
                        // a first child 0 makes the value an array without a look-up
                        if ((token_size == 1 && data[pos + 1] == '0') || arrays.contains(data, pos))
                        {
                            // some reference token below this position is 0, so the
                            // value is an array
                            *current = BasicJsonType(detail::value_t::array);
                            reserve_elements(*current->m_data.m_value.array, 2, detail::priority_tag<1> {});
                            current = &current->operator[](array_index<BasicJsonType>(token));
                        }
                        else
                        {
                            // start a new object otherwise
                            current = &current->operator[](token);
                        }
                        break;
                    }

                    case detail::value_t::object:
                    {
                        // create an entry in the object
                        current = &object_member(*current, token);
                        break;
                    }

                    case detail::value_t::array:
                    {
                        // create an entry in the array
                        current = &current->operator[](array_index<BasicJsonType>(token));
                        break;
                    }

                    /*
                    The following code is only reached if there exists a reference
                    token _and_ the current value is primitive. In this case, we have
                    an error situation, because primitive values may only occur as
                    a single value; that is, with an empty list of reference tokens.
                    */
                    case detail::value_t::string:
                    case detail::value_t::boolean:
                    case detail::value_t::number_integer:
                    case detail::value_t::number_unsigned:
                    case detail::value_t::number_float:
                    case detail::value_t::binary:
                    case detail::value_t::discarded:
                    default:
                        JSON_THROW(detail::type_error::create(detail::exception_id::unflatten_invalid_value, "invalid value to unflatten", &result));
                }

                values.push_back(current);
                ends.push_back(end);
                pos = end;
            }

            *current = element.second;
        }

        return result;
    }

    // can't use the conversion operator because of ambiguity
    json_pointer<string_t> convert() const&
    {
        json_pointer<string_t> result;
        result.reference_tokens = reference_tokens;
        return result;
    }

    json_pointer<string_t> convert()&&
    {
        json_pointer<string_t> result;
        result.reference_tokens = std::move(reference_tokens);
        return result;
    }

  public:
#if JSON_HAS_THREE_WAY_COMPARISON
    /// @brief compares two JSON pointers for equality
    /// @sa https://json.nlohmann.me/api/json_pointer/operator_eq/
    template<typename RefStringTypeRhs>
    bool operator==(const json_pointer<RefStringTypeRhs>& rhs) const noexcept
    {
        return reference_tokens == rhs.reference_tokens;
    }

    /// @brief compares JSON pointer and string for equality
    /// @sa https://json.nlohmann.me/api/json_pointer/operator_eq/
    JSON_HEDLEY_DEPRECATED_FOR(3.11.2, operator==(json_pointer))
    bool operator==(const string_t& rhs) const
#if JSON_DELETE_DEPRECATED_FUNCTIONS
        = delete;
#else
    {
        return equals_string(rhs);
    }
#endif

    /// @brief 3-way compares two JSON pointers
    template<typename RefStringTypeRhs>
    std::strong_ordering operator<=>(const json_pointer<RefStringTypeRhs>& rhs) const noexcept // *NOPAD*
    {
        return  reference_tokens <=> rhs.reference_tokens; // *NOPAD*
    }
#else
    /// @brief compares two JSON pointers for equality
    /// @sa https://json.nlohmann.me/api/json_pointer/operator_eq/
    template<typename RefStringTypeLhs, typename RefStringTypeRhs>
    // NOLINTNEXTLINE(readability-redundant-declaration)
    friend bool operator==(const json_pointer<RefStringTypeLhs>& lhs,
                           const json_pointer<RefStringTypeRhs>& rhs) noexcept;

    /// @brief compares JSON pointer and string for equality
    /// @sa https://json.nlohmann.me/api/json_pointer/operator_eq/
    template<typename RefStringTypeLhs, typename StringType>
    // NOLINTNEXTLINE(readability-redundant-declaration)
    friend bool operator==(const json_pointer<RefStringTypeLhs>& lhs,
                           const StringType& rhs);

    /// @brief compares string and JSON pointer for equality
    /// @sa https://json.nlohmann.me/api/json_pointer/operator_eq/
    template<typename RefStringTypeRhs, typename StringType>
    // NOLINTNEXTLINE(readability-redundant-declaration)
    friend bool operator==(const StringType& lhs,
                           const json_pointer<RefStringTypeRhs>& rhs);

    /// @brief compares two JSON pointers for inequality
    /// @sa https://json.nlohmann.me/api/json_pointer/operator_ne/
    template<typename RefStringTypeLhs, typename RefStringTypeRhs>
    // NOLINTNEXTLINE(readability-redundant-declaration)
    friend bool operator!=(const json_pointer<RefStringTypeLhs>& lhs,
                           const json_pointer<RefStringTypeRhs>& rhs) noexcept;

    /// @brief compares JSON pointer and string for inequality
    /// @sa https://json.nlohmann.me/api/json_pointer/operator_ne/
    template<typename RefStringTypeLhs, typename StringType>
    // NOLINTNEXTLINE(readability-redundant-declaration)
    friend bool operator!=(const json_pointer<RefStringTypeLhs>& lhs,
                           const StringType& rhs);

    /// @brief compares string and JSON pointer for inequality
    /// @sa https://json.nlohmann.me/api/json_pointer/operator_ne/
    template<typename RefStringTypeRhs, typename StringType>
    // NOLINTNEXTLINE(readability-redundant-declaration)
    friend bool operator!=(const StringType& lhs,
                           const json_pointer<RefStringTypeRhs>& rhs);

    /// @brief compares two JSON pointers for less-than
    /// @sa https://json.nlohmann.me/api/json_pointer/operator_spaceship/
    template<typename RefStringTypeLhs, typename RefStringTypeRhs>
    // NOLINTNEXTLINE(readability-redundant-declaration)
    friend bool operator<(const json_pointer<RefStringTypeLhs>& lhs,
                          const json_pointer<RefStringTypeRhs>& rhs) noexcept;
#endif

  private:
    /// the reference tokens
    std::vector<string_t> reference_tokens;
};

#if !JSON_HAS_THREE_WAY_COMPARISON
// functions cannot be defined inside the class due to ODR violations
template<typename RefStringTypeLhs, typename RefStringTypeRhs>
inline bool operator==(const json_pointer<RefStringTypeLhs>& lhs,
                       const json_pointer<RefStringTypeRhs>& rhs) noexcept
{
    return lhs.reference_tokens == rhs.reference_tokens;
}

template<typename RefStringTypeLhs,
         typename StringType = typename json_pointer<RefStringTypeLhs>::string_t>
JSON_HEDLEY_DEPRECATED_FOR(3.11.2, operator==(json_pointer, json_pointer))
inline bool operator==(const json_pointer<RefStringTypeLhs>& lhs,
                       const StringType& rhs)
#if JSON_DELETE_DEPRECATED_FUNCTIONS
    = delete;
#else
{
    return lhs.equals_string(rhs);
}
#endif

template<typename RefStringTypeRhs,
         typename StringType = typename json_pointer<RefStringTypeRhs>::string_t>
JSON_HEDLEY_DEPRECATED_FOR(3.11.2, operator==(json_pointer, json_pointer))
inline bool operator==(const StringType& lhs,
                       const json_pointer<RefStringTypeRhs>& rhs)
#if JSON_DELETE_DEPRECATED_FUNCTIONS
    = delete;
#else
{
    return rhs.equals_string(lhs);
}
#endif

template<typename RefStringTypeLhs, typename RefStringTypeRhs>
inline bool operator!=(const json_pointer<RefStringTypeLhs>& lhs,
                       const json_pointer<RefStringTypeRhs>& rhs) noexcept
{
    return !(lhs == rhs);
}

template<typename RefStringTypeLhs,
         typename StringType = typename json_pointer<RefStringTypeLhs>::string_t>
JSON_HEDLEY_DEPRECATED_FOR(3.11.2, operator!=(json_pointer, json_pointer))
inline bool operator!=(const json_pointer<RefStringTypeLhs>& lhs,
                       const StringType& rhs)
#if JSON_DELETE_DEPRECATED_FUNCTIONS
    = delete;
#else
{
    return !(lhs == rhs);
}
#endif

template<typename RefStringTypeRhs,
         typename StringType = typename json_pointer<RefStringTypeRhs>::string_t>
JSON_HEDLEY_DEPRECATED_FOR(3.11.2, operator!=(json_pointer, json_pointer))
inline bool operator!=(const StringType& lhs,
                       const json_pointer<RefStringTypeRhs>& rhs)
#if JSON_DELETE_DEPRECATED_FUNCTIONS
    = delete;
#else
{
    return !(lhs == rhs);
}
#endif

template<typename RefStringTypeLhs, typename RefStringTypeRhs>
inline bool operator<(const json_pointer<RefStringTypeLhs>& lhs,
                      const json_pointer<RefStringTypeRhs>& rhs) noexcept
{
    return lhs.reference_tokens < rhs.reference_tokens;
}
#endif

namespace detail
{
/// the reference tokens of a json_pointer, for code that resolves pointers
/// without a basic_json value (such as the zero-copy view)
struct json_pointer_access
{
    template<typename RefStringType>
    static const std::vector<typename json_pointer<RefStringType>::string_t>& reference_tokens(const json_pointer<RefStringType>& ptr) noexcept
    {
        return ptr.reference_tokens;
    }
};
}  // namespace detail

NLOHMANN_JSON_NAMESPACE_END
