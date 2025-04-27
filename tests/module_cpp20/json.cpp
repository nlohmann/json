module;
#include <nlohmann/json.hpp>
export module json;

export namespace nlohmann
{
using ::nlohmann::adl_serializer;

using ::nlohmann::basic_json;
using ::nlohmann::json_pointer;

using ::nlohmann::json;
using ::nlohmann::ordered_json;
using ::nlohmann::ordered_map;

using ::nlohmann::json_pointer;
}  // namespace nlohmann
