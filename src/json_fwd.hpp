#ifndef NLOHMANN_JSON_FWD_HPP
#define NLOHMANN_JSON_FWD_HPP

#include <cstdint>
#include <map>
#include <vector>
#include <string>

namespace nlohmann
{

template <
    template<typename U, typename V, typename... Args> class ObjectType,
    template<typename U, typename... Args> class ArrayType,
    class StringType,
    class BooleanType,
    class NumberIntegerType,
    class NumberUnsignedType,
    class NumberFloatType,
    template<typename U> class AllocatorType
    >
class basic_json;

using json = basic_json<std::map,std::vector,std::string,bool,std::int64_t,
                        std::uint64_t,double,std::allocator>;

} // namespace nlohmann

#endif // NLOHMANN_JSON_FWD_HPP

