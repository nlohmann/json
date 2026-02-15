module;

#include <nlohmann/json.hpp>

export module nlohmann.json;

export namespace nlohmann {
    using ::nlohmann::adl_serializer;
    using ::nlohmann::basic_json;
    using ::nlohmann::json;
    using ::nlohmann::json_pointer;
    using ::nlohmann::ordered_json;
    using ::nlohmann::ordered_map;
}  // namespace nlohmann

NLOHMANN_JSON_NAMESPACE_BEGIN

namespace detail
{
    export using NLOHMANN_JSON_NAMESPACE::detail::json_sax_dom_callback_parser;
    export using NLOHMANN_JSON_NAMESPACE::detail::unknown_size;
} // namespace detail

export using NLOHMANN_JSON_NAMESPACE::adl_serializer;
export using NLOHMANN_JSON_NAMESPACE::basic_json;
export using NLOHMANN_JSON_NAMESPACE::json;
export using NLOHMANN_JSON_NAMESPACE::json_pointer;
export using NLOHMANN_JSON_NAMESPACE::ordered_json;
export using NLOHMANN_JSON_NAMESPACE::ordered_map;
export using NLOHMANN_JSON_NAMESPACE::to_string;

NLOHMANN_JSON_NAMESPACE_END
