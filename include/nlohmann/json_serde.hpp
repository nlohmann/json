//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#ifndef INCLUDE_NLOHMANN_JSON_SERDE_HPP_
#define INCLUDE_NLOHMANN_JSON_SERDE_HPP_

#include <nlohmann/detail/macro_scope.hpp>

// The reflection-based serde layer requires reflection together with annotations.
// Compiled only when the toolchain advertises __cpp_impl_reflection.
#if JSON_HAS_REFLECTION

#include <meta>         // std::meta reflection facilities
#include <iterator>     // begin, end
#include <optional>     // optional
#include <string>       // string
#include <string_view>  // string_view
#include <type_traits>  // is_class, is_enum, remove_cvref_t, underlying_type_t
#include <utility>      // declval
#include <vector>       // vector

#include <nlohmann/detail/exceptions.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN

namespace detail
{
namespace serde
{
struct transient_t {};
struct flatten_t {};
struct reflectable_t {};
struct allow_private_t {};
}  // namespace serde
}  // namespace detail

/*!
@brief field annotation: exclude a member from (de)serialization

@ref basic_json::serialize skips the member on the way
out and @ref basic_json::deserialize leaves it default-initialized on the way in.

@code{.cpp}
struct Session {
    std::string user;
    [[=nlohmann::transient]] std::string password;   // never serialized
};
@endcode

@since version 3.12.0
*/
inline constexpr detail::serde::transient_t transient;

/*!
@brief field annotation: inline a nested struct's keys into the parent object

Instead of nesting the member under its own key, its members are written at the
parent level on serialize and read from the parent level on deserialize.

@since version 3.12.0
*/
inline constexpr detail::serde::flatten_t flatten;

/*!
@brief type annotation: allow serde to reach a type's private/protected members

Plain structs with only public data members need no annotation. Apply this to a
class with private members to permit the serializer to read and write them. The
global @ref JSON_SERDE_ALLOW_PRIVATE knob lifts the requirement for every type.

@code{.cpp}
class [[=nlohmann::reflectable]] Account {
    std::string owner;
    long balance = 0;
};
@endcode

@since version 3.12.0
*/
inline constexpr detail::serde::reflectable_t reflectable;

/*!
@brief call-site tag: allow serde to reach private/protected members for one call

Pass this as the second argument to @ref basic_json::serialize or to a
`deserialize` call to grant access to the private and protected data members of
`T` for that call only, without annotating the type. This is the way to
(de)serialize a type you do not own, since an attribute can only be attached to
a type at its definition.

@code{.cpp}
// Stranger is a third-party type with private members and a public default ctor
json j = json::serialize(obj, nlohmann::allow_private);
auto back = j.deserialize<Stranger>(nlohmann::allow_private);
@endcode

@sa @ref reflectable - the equivalent as a type annotation, when you own the type
@sa @ref JSON_SERDE_ALLOW_PRIVATE - the equivalent for every type in a translation unit

@since version 3.13.0
*/
inline constexpr detail::serde::allow_private_t allow_private;

/*!
@brief field annotation: use a different JSON key than the member name

@code{.cpp}
struct Config {
    [[=nlohmann::rename("listen-port")]] int port;   // keyed as "listen-port"
};
@endcode

@since version 3.12.0
*/
template<std::size_t N>
struct rename
{
    // flawfinder: ignore (compile-time-only buffer; its size N is the same template
    // parameter as its sole source str, so the consteval copy below cannot overflow)
    char value[N];
    consteval rename(const char (&str)[N]) noexcept // NOLINT(google-explicit-constructor,hicpp-explicit-conversions)
    {
        for (std::size_t i = 0; i < N; ++i)
        {
            value[i] = str[i];
        }
    }
};
template<std::size_t N>
rename(const char (&)[N]) -> rename<N>;

namespace detail
{
namespace serde
{

// The (dealiased, const-stripped) type of an annotation reflection.
JSON_HEDLEY_WARN_UNUSED_RESULT
consteval std::meta::info annotation_type(std::meta::info a)
{
    return std::meta::remove_const(std::meta::dealias(std::meta::type_of(a)));
}

// true when the reflected entity Mem carries an annotation of type Tag.
template<typename Tag, std::meta::info Mem>
JSON_HEDLEY_WARN_UNUSED_RESULT
consteval bool has_annotation()
{
    template for (constexpr std::meta::info a : std::define_static_array(std::meta::annotations_of(Mem)))
    {
        if (annotation_type(a) == ^^Tag)
        {
            return true;
        }
    }
    return false;
}

// The renamed string if [[=nlohmann::rename(...)]] is present, otherwise the member's own identifier.
template<std::meta::info Mem>
JSON_HEDLEY_WARN_UNUSED_RESULT
consteval std::string_view member_key()
{
    template for (constexpr std::meta::info a : std::define_static_array(std::meta::annotations_of(Mem)))
    {
        constexpr std::meta::info t = annotation_type(a);
        if constexpr (std::meta::has_template_arguments(t) && std::meta::template_of(t) == ^^rename)
        {
            constexpr std::meta::info r = std::meta::extract<typename[:t:]>(a);
            return std::define_static_string(std::string_view{r.value, sizeof(r.value) - 1});
        }
    }
    return std::meta::identifier_of(Mem);
}

// Whether private/protected members of T may be reached. AllowPrivate is the
// per-call opt-in (the nlohmann::allow_private tag); it ORs with the reflectable
// type annotation and the global JSON_SERDE_ALLOW_PRIVATE knob.
template<typename T, bool AllowPrivate = false>
JSON_HEDLEY_WARN_UNUSED_RESULT
consteval bool is_reflectable_type()
{
    return AllowPrivate || JSON_SERDE_ALLOW_PRIVATE != 0 || has_annotation<reflectable_t,^^ T>();
}

template<typename T, bool AllowPrivate = false>
JSON_HEDLEY_WARN_UNUSED_RESULT
consteval std::meta::access_context serde_access()
{
    if constexpr (is_reflectable_type<T, AllowPrivate>())
    {
        return std::meta::access_context::unchecked();
    }
    else
    {
        return std::meta::access_context::current();
    }
}

template<typename T, typename = void>
struct is_iterable_leaf : std::false_type {};
template<typename T>
struct is_iterable_leaf<T, decltype(
    void(std::begin(std::declval<T&>())),
    void(std::end(std::declval<T&>())))> : std::true_type {};

template<typename T>
struct is_optional_leaf : std::false_type {};
template<typename T>
struct is_optional_leaf<std::optional<T>> : std::true_type {};

template<typename T>
inline constexpr bool is_serde_struct =
    std::is_class_v<std::remove_cvref_t<T>>
    && !is_basic_json<std::remove_cvref_t<T>>::value
    && !std::is_same_v<std::remove_cvref_t<T>, std::string>
    && !is_iterable_leaf<std::remove_cvref_t<T>>::value
    && !is_optional_leaf<std::remove_cvref_t<T>>::value;

// Whether a type the serde core should map member-by-member via reflection.
template<typename T>
concept serde_struct = is_serde_struct<T>;

// Whether the user supplied an ADL to_json for T (as a hand-written overload
// or a NLOHMANN_DEFINE_TYPE_* expansion), in which case the reflection fallback
// must stand aside.
template<typename BasicJsonType, typename T>
concept has_adl_to_json = requires(BasicJsonType& j, const T& val)
{
    to_json(j, val);
};

// Whether the user supplied an ADL from_json for T (as a hand-written overload
// or a NLOHMANN_DEFINE_TYPE_* expansion), in which case the reflection fallback
// must stand aside.
template<typename BasicJsonType, typename T>
concept has_adl_from_json = requires(const BasicJsonType& j, T& val)
{
    from_json(j, val);
};

template<typename E>
JSON_HEDLEY_WARN_UNUSED_RESULT
std::string enum_to_name(E value)
{
    template for (constexpr std::meta::info e : std::define_static_array(std::meta::enumerators_of(^^E)))
    {
        if (value == [:e:])
        {
            return std::string(std::meta::identifier_of(e));
        }
    }
    // An unknown enumerator (e.g. a value formed by a cast) has no name; fall
    // back to its integral form so the information is not silently dropped.
    return std::to_string(static_cast<std::underlying_type_t<E>>(value));
}

template<typename E>
JSON_HEDLEY_WARN_UNUSED_RESULT
bool enum_from_name(std::string_view name, E& out)
{
    template for (constexpr std::meta::info e : std::define_static_array(std::meta::enumerators_of(^^E)))
    {
        if (name == std::meta::identifier_of(e))
        {
            out = [:e:];
            return true;
        }
    }
    return false;
}

// Centralizes failure reporting during deserialize().
struct serde_sink
{
    void fail(exception_id id_, const std::string& what_arg)
    {
        failed_ = true;
        JSON_THROW(deserialization_error::create(id_, what_arg, nullptr));
    }

    JSON_HEDLEY_WARN_UNUSED_RESULT
    bool failed() const noexcept
    {
        return failed_;
    }

  private:
    bool failed_ = false;
};

// Append to out every JSON key that T contributes to its enclosing object, checking it for duplicates
template<typename T, bool AllowPrivate = false>
consteval void collect_serde_keys(std::vector<std::string_view>& out)
{
    template for (constexpr std::meta::info member :
                  std::define_static_array(std::meta::nonstatic_data_members_of(^^T, serde_access<T, AllowPrivate>())))
    {
        if constexpr (!has_annotation<transient_t, member>())
        {
            using member_t = typename[:std::meta::type_of(member):];
            if constexpr (has_annotation<flatten_t, member>() && is_serde_struct<member_t>)
            {
                // a flattened struct is reached through its public members only;
                // AllowPrivate governs the top-level type the user named
                collect_serde_keys<member_t>(out);
            }
            else
            {
                out.push_back(member_key<member>());
            }
        }
    }
}

// The first JSON key that appears more than once in T's flattened key set, or
// no value if there is no collision.
template<typename T, bool AllowPrivate = false>
consteval std::optional<std::string_view> first_duplicate_serde_key()
{
    std::vector<std::string_view> keys;
    collect_serde_keys<T, AllowPrivate>(keys);
    for (std::size_t i = 0; i < keys.size(); ++i)
    {
        for (std::size_t k = i + 1; k < keys.size(); ++k)
        {
            if (keys[i] == keys[k])
            {
                return keys[i];
            }
        }
    }
    return std::nullopt;
}

// Reject a colliding key at compile time when flattening a nested struct
template<typename T, bool AllowPrivate = false>
inline constexpr bool has_no_serde_key_collision = !first_duplicate_serde_key<T, AllowPrivate>().has_value();

// Walk a serde struct into a JSON object.
template<bool AllowPrivate = false, typename BasicJsonType, typename T>
void serialize_struct(BasicJsonType& j, const T& obj)
{
    static_assert(has_no_serde_key_collision<T, AllowPrivate>,
                  "a [[=nlohmann::flatten]] member collides with another JSON key; "
                  "rename one of them so every key in the flattened object is unique");
    j = BasicJsonType::object();
    template for (constexpr std::meta::info member :
                  std::define_static_array(std::meta::nonstatic_data_members_of(^^T, serde_access<T, AllowPrivate>())))
    {
        if constexpr (!has_annotation<transient_t, member>())
        {
            using member_t = typename[:std::meta::type_of(member):];
            const auto& field = obj.[:member:];

            if constexpr (has_annotation<flatten_t, member>() && is_serde_struct<member_t>)
            {
                BasicJsonType sub;
                serialize_struct(sub, field);
                for (auto it = sub.begin(); it != sub.end(); ++it)
                {
                    j[it.key()] = std::move(it.value());
                }
            }
            else if constexpr (std::is_enum_v<member_t>)
            {
                j[std::string(member_key<member>())] = enum_to_name(field);
            }
            else
            {
                // assignment routes through adl_serializer; a member that is
                // itself a serde struct (directly, or inside a container or
                // optional) comes back through the reflection fallback there
                j[std::string(member_key<member>())] = field;
            }
        }
    }
}

template<bool AllowPrivate = false, typename T, typename BasicJsonType>
void deserialize_struct(const BasicJsonType& j, T& out);

// Fill a single member from node n (already located in the parent object).
template<typename Mem, typename BasicJsonType>
void deserialize_member(const BasicJsonType& n, Mem& out, std::string_view key)
{
    if constexpr (std::is_enum_v<Mem>)
    {
        if (!n.is_string() || !enum_from_name<Mem>(n.template get<std::string>(), out))
        {
            serde_sink{}.fail(exception_id::unknown_enumerator,
                              concat("member '", std::string(key), "' is not a known enumerator name"));
        }
    }
    else if constexpr (is_serde_struct<Mem>)
    {
        if (!n.is_object())
        {
            serde_sink{}.fail(exception_id::deserialization_type_mismatch,
                              concat("member '", std::string(key), "' must be a JSON object"));
            return;
        }
        // a nested serde-struct member is reached through its public members
        deserialize_struct<false>(n, out);
    }
    else
    {
        n.get_to(out);  // defers to adl_serializer / from_json (and the fallback)
    }
}

template<bool AllowPrivate, typename T, typename BasicJsonType>
void deserialize_struct(const BasicJsonType& j, T& out)
{
    static_assert(has_no_serde_key_collision<T, AllowPrivate>,
                  "a [[=nlohmann::flatten]] member collides with another JSON key; "
                  "rename one of them so every key in the flattened object is unique");
    template for (constexpr std::meta::info member :
                  std::define_static_array(std::meta::nonstatic_data_members_of(^^T, serde_access<T, AllowPrivate>())))
    {
        if constexpr (!has_annotation<transient_t, member>())
        {
            using member_t = typename[:std::meta::type_of(member):];
            constexpr std::string_view key = member_key<member>();

            if constexpr (has_annotation<flatten_t, member>() && is_serde_struct<member_t>)
            {
                // a flattened struct reads through its public members
                deserialize_struct<false>(j, out.[:member:]);
            }
            else if (const auto it = j.find(std::string(key)); it != j.end() && !it->is_null())
            {
                deserialize_member(*it, out.[:member:], key);
            }
            // A missing or null key leaves the member at its default, so
            // defaulted and optional members need no special handling.
        }
    }
}

}  // namespace serde
}  // namespace detail

NLOHMANN_JSON_NAMESPACE_END

#endif  // JSON_HAS_REFLECTION

#endif  // INCLUDE_NLOHMANN_JSON_SERDE_HPP_
