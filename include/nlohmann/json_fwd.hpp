#ifndef INCLUDE_NLOHMANN_JSON_FWD_HPP_
#define INCLUDE_NLOHMANN_JSON_FWD_HPP_

#include <cstdint> // int64_t, uint64_t
#include <map> // map
#include <memory> // allocator
#include <string> // string
#include <vector> // vector

/*!
@brief namespace for Niels Lohmann
@see https://github.com/nlohmann
@since version 1.0.0
*/
namespace nlohmann
{
/*!
@brief default JSONSerializer template argument

This serializer ignores the template arguments and uses ADL
([argument-dependent lookup](https://en.cppreference.com/w/cpp/language/adl))
for serialization.
*/
template<typename T = void, typename SFINAE = void>
struct adl_serializer;

/// a class to store JSON values
/// @sa https://json.nlohmann.me/api/basic_json/
template<template<typename U, typename V, typename... Args> class ObjectType =
         std::map,
         template<typename U, typename... Args> class ArrayType = std::vector,
         class StringType = std::string, class BooleanType = bool,
         class NumberIntegerType = std::int64_t,
         class NumberUnsignedType = std::uint64_t,
         class NumberFloatType = double,
         template<typename U> class AllocatorType = std::allocator,
         template<typename T, typename SFINAE = void> class JSONSerializer =
         adl_serializer,
         class BinaryType = std::vector<std::uint8_t>>
class basic_json;

/// @brief JSON Pointer defines a string syntax for identifying a specific value within a JSON document
/// @sa https://json.nlohmann.me/api/json_pointer/
template<typename BasicJsonType>
class json_pointer;

/*!
@brief default specialization
@sa https://json.nlohmann.me/api/json/
*/
using json = basic_json<>;

/// @brief a minimal map-like container that preserves insertion order
/// @sa https://json.nlohmann.me/api/ordered_map/
template<class Key, class T, class IgnoredLess, class Allocator>
struct ordered_map;

/// @brief specialization that maintains the insertion order of object keys
/// @sa https://json.nlohmann.me/api/ordered_json/
using ordered_json = basic_json<nlohmann::ordered_map>;

}  // namespace nlohmann

#endif  // INCLUDE_NLOHMANN_JSON_FWD_HPP_
