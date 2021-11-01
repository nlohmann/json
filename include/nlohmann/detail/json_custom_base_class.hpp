#pragma once

#include <type_traits> // conditional, is_same

namespace nlohmann
{
namespace detail
{

/*!
@brief Default base class of the @ref basic_json class.

So that the correct implementation of the copy / move ctors / assign operators
of @ref basic_json does not require complex case distinctions
(no base class / custom base class), @ref basic_json always a base class.
By default this class is used, since empty and thus has no effect on the
behaviour of @ref basic_json.


So that the correct implementation of the copy / move ctors / assign operators
of @ref basic_json does not require complex case distinctions
(no base class / custom base class used as customization point),
@ref basic_json always has a base class.
By default, this class is used because it is empty and thus has no effect
on the behavior of @ref basic_json.
*/
struct json_default_base {};

template<class T>
using json_base_class = typename std::conditional <
                        std::is_same<T, void>::value,
                        json_default_base,
                        T
                        >::type;

}  // namespace detail
}  // namespace nlohmann
