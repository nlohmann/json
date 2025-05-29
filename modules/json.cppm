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
