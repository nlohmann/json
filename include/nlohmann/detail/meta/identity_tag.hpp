#pragma once

namespace nlohmann
{
namespace detail
{
// dispatching helper struct
template <class T> struct identity_tag {};
}  // namespace detail
}  // namespace nlohmann
