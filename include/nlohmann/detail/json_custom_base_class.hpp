#pragma once

#include <type_traits>

namespace nlohmann
{
namespace detail
{

struct json_default_base {};

template<class T>
using json_base_class = typename std::conditional <
                        std::is_same<T, void>::value,
                        json_default_base,
                        T
                        >::type;

}  // namespace detail
}  // namespace nlohmann
