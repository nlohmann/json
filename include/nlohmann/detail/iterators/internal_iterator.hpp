#pragma once

#include <nlohmann/detail/iterators/primitive_iterator.hpp>

namespace nlohmann
{
namespace detail
{
/*!
@brief an iterator value

@note This structure could easily be a union, but MSVC currently does not allow
unions members with complex constructors, see https://github.com/nlohmann/json/pull/105.
*/
template<typename BasicJsonType> struct internal_iterator
{
    /// iterator for JSON objects
    typename BasicJsonType::object_t::iterator object_iterator {};
    /// iterator for JSON arrays
    typename BasicJsonType::array_t::iterator array_iterator {};
    /// iterator for JSON binary arrays
    typename BasicJsonType::binary_t::container_type::iterator binary_iterator {};
    /// generic iterator for all other types
    primitive_iterator_t primitive_iterator {};
};
}  // namespace detail
}  // namespace nlohmann
