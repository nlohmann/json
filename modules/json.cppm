module;

#include <nlohmann/json.hpp>

export module nlohmann.json;

export namespace nlohmann {
    template <typename T = void, typename SFINAE = void>
    using adl_serializer = ::nlohmann::adl_serializer<T, SFINAE>;

    using basic_json = ::nlohmann::basic_json<>;

    using json = ::nlohmann::json;

    template <typename RefStringType>
    using json_pointer = ::nlohmann::json_pointer<RefStringType>;

    using ::nlohmann::ordered_json;

    template <class Key, class T, class IgnoredLess, class Allocator>
    using ordered_map = ::nlohmann::ordered_map<Key, T, IgnoredLess, Allocator>;
}  // namespace nlohmann
