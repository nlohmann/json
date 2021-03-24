#pragma once

#include <string>
#include <nlohmann/detail/macro_scope.hpp>

namespace nlohmann
{
namespace detail
{

/*!
@brief replace all occurrences of a substring by another string

@param[in,out] s  the string to manipulate; changed so that all
               occurrences of @a f are replaced with @a t
@param[in]     f  the substring to replace with @a t
@param[in]     t  the string to replace @a f

@pre The search string @a f must not be empty. **This precondition is
enforced with an assertion.**

@since version 2.0.0
*/
inline void replace_substring(std::string& s, const std::string& f,
                              const std::string& t)
{
    JSON_ASSERT(!f.empty());
    for (auto pos = s.find(f);                // find first occurrence of f
            pos != std::string::npos;         // make sure f was found
            s.replace(pos, f.size(), t),      // replace with t, and
            pos = s.find(f, pos + t.size()))  // find next occurrence of f
    {}
}

/*!
 * @brief string escaping as described in RFC 6901 (Sect. 4)
 * @param[in] s string to escape
 * @return    escaped string
 *
 * Note the order of escaping "~" to "~0" and "/" to "~1" is important.
 */
inline std::string escape(std::string s)
{
    replace_substring(s, "~", "~0");
    replace_substring(s, "/", "~1");
    return s;
}

/*!
 * @brief string unescaping as described in RFC 6901 (Sect. 4)
 * @param[in] s string to unescape
 * @return    unescaped string
 *
 * Note the order of escaping "~1" to "/" and "~0" to "~" is important.
 */
static void unescape(std::string& s)
{
    replace_substring(s, "~1", "/");
    replace_substring(s, "~0", "~");
}

} // namespace detail
} // namespace nlohmann
