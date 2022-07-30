#pragma once

#include <nlohmann/detail/macro_scope.hpp>

#if JSON_HAS_EXPERIMENTAL_FILESYSTEM
#include <experimental/filesystem>
NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace std_fs = std::experimental::filesystem;
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
#elif JSON_HAS_FILESYSTEM
#include <filesystem>
NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace std_fs = std::filesystem;
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
#endif
