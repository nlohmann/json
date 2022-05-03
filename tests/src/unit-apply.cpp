#include "doctest_compatibility.h"

DOCTEST_CLANG_SUPPRESS_WARNING_PUSH
DOCTEST_CLANG_SUPPRESS_WARNING("-Wshorten-64-to-32")
DOCTEST_CLANG_SUPPRESS_WARNING("-Wfloat-conversion")
DOCTEST_CLANG_SUPPRESS_WARNING("-Wimplicit-int-float-conversion")
DOCTEST_CLANG_SUPPRESS_WARNING("-Wsign-conversion")

DOCTEST_GCC_SUPPRESS_WARNING_PUSH
DOCTEST_GCC_SUPPRESS_WARNING("-Wconversion")
DOCTEST_GCC_SUPPRESS_WARNING("-Wfloat-conversion")
DOCTEST_GCC_SUPPRESS_WARNING("-Wsign-conversion")

DOCTEST_MSVC_SUPPRESS_WARNING_PUSH
DOCTEST_MSVC_SUPPRESS_WARNING(4244) // 'conversion' conversion from 'type1' to 'type2', possible loss of data
DOCTEST_MSVC_SUPPRESS_WARNING(4267) // 'var' : conversion from 'size_t' to 'type', possible loss of data
#include <nlohmann/json.hpp>
using nlohmann::json;

#include <cstdint>

#if JSON_HAS_RANGES
    // JSON_HAS_CPP_20 (magic keyword; do not remove)
    #include <ranges>
#endif

// MSSTL defines as_const in the global namespace :facepalm:
template<typename... Args>
static auto const_(Args&& ... args) -> decltype(nlohmann::detail::as_const(std::forward<Args>(args)...))
{
    return nlohmann::detail::as_const(std::forward<Args>(args)...);
}

static void array_push_back(json::array_t& arr, json val)
{
    arr.emplace_back(std::move(val));
}

static void array_push_front(json val, json::array_t& arr)
{
    arr.emplace(arr.begin(), std::move(val));
}

struct foo
{
    int bar = 0;
    void set_bar(int i) noexcept
    {
        bar = i;
    }

    static int static_bar;
    static void static_set_bar(int i) noexcept
    {
        static_bar = i;
    }
};

int foo::static_bar = 0;

struct functor
{
    int arg;
    int value = 0;

    explicit functor(int arg_ = 0) noexcept : arg(arg_) {}

    void operator()(int a, int b = 0, int c = 0) noexcept
    {
        switch (arg)
        {
            default:
            case 0:
                value = a;
                break;
            case 1:
                value = b;
                break;
            case 2:
                value = c;
                break;
        }
    }
};

static int get_value(int i) noexcept
{
    return i;
}

static int callback_value = 0;

static void callback(int i) noexcept
{
    callback_value = i;
}

struct not_an_int
{
    explicit not_an_int() = default;
};

static not_an_int get_not_an_int(int /*unused*/)
{
    return not_an_int{};
}

TEST_CASE("apply*() functions")
{
    SECTION("placeholder")
    {
        using nlohmann::placeholders::basic_json_value;
        using nlohmann::detail::is_basic_json_value_placeholder;
        CHECK(std::is_same<decltype(basic_json_value), decltype(json::value_placeholder)>::value);
        CHECK(is_basic_json_value_placeholder<decltype(json::value_placeholder)>::value);
        CHECK_FALSE(is_basic_json_value_placeholder<json>::value);
    }

    SECTION("apply()")
    {
        SECTION("plain function")
        {
            SECTION("const")
            {
                const json j = json::array({"foo"});
                CHECK_THROWS_WITH_AS(j.apply(array_push_back, 42),
                                     "[json.exception.type_error.318] cannot invoke callable with const JSON value of type array",
                                     json::type_error&);
            }

            SECTION("non-const")
            {
                SECTION("without explicit placeholder")
                {
                    json j = json::array({"foo"});
                    json j_expected = json::array({"foo", 42});

                    j.apply(array_push_back, 42);

                    CHECK(j == j_expected);
                }

                SECTION("with explicit placeholder")
                {
                    json j = json::array({"foo"});
                    json j_expected = json::array({42, "foo"});
                    json j_expected2 = json::array({42, "foo", 24});

                    j.apply(array_push_front, 42, json::value_placeholder);

                    CHECK(j == j_expected);

                    j.apply(array_push_back, json::value_placeholder, 24);

                    CHECK(j == j_expected2);
                }
            }
        }

        SECTION("static member function pointer")
        {
            json j(42);

            SECTION("const (without explicit placeholder)")
            {
                foo::static_bar = 0;
                const_(j).apply(&foo::static_set_bar);

                CHECK(foo::static_bar == 42);
                CHECK(j == 42);
            }

            SECTION("const (with explicit placeholder)")
            {
                foo::static_bar = 0;
                const_(j).apply(&foo::static_set_bar, json::value_placeholder);

                CHECK(foo::static_bar == 42);
                CHECK(j == 42);
            }

            SECTION("non-const (without explicit placeholder)")
            {
                foo::static_bar = 0;
                j.apply(&foo::static_set_bar);

                CHECK(foo::static_bar == 42);
                CHECK(j == 42);
            }

            SECTION("non-const (with explicit placeholder)")
            {
                foo::static_bar = 0;
                j.apply(&foo::static_set_bar, json::value_placeholder);

                CHECK(foo::static_bar == 42);
                CHECK(j == 42);
            }
        }

        SECTION("non-static member function pointer")
        {
            json j(42);

            SECTION("const (without explicit placeholder)")
            {
                foo f;

                const_(j).apply(&foo::set_bar, f);

                CHECK(f.bar == 42);
                CHECK(j == 42);
            }

            SECTION("const (with explicit placeholder)")
            {
                foo f;

                const_(j).apply(&foo::set_bar, f, json::value_placeholder);

                CHECK(f.bar == 42);
                CHECK(j == 42);
            }

            SECTION("non-const (without explicit placeholder)")
            {
                foo f;

                j.apply(&foo::set_bar, f);

                CHECK(f.bar == 42);
                CHECK(j == 42);
            }

            SECTION("non-const (with explicit placeholder)")
            {
                foo f;

                j.apply(&foo::set_bar, f, json::value_placeholder);

                CHECK(f.bar == 42);
                CHECK(j == 42);
            }
        }

        SECTION("non-static function member pointer (json::array_t::resize)")
        {
            json j = json::array();
            json j_expected = json::array({42, 42});

            SECTION("const")
            {
                CHECK_THROWS_WITH_AS(const_(j).apply(static_cast<void (json::array_t::*)(json::array_t::size_type, const json&)>(&json::array_t::resize), json::value_placeholder, 2, json(42)),
                                     "[json.exception.type_error.318] cannot invoke callable with const JSON value of type array",
                                     json::type_error&);
                CHECK(j.empty());
            }

            SECTION("non-const (without explicit placeholder)")
            {
                CHECK_THROWS_WITH_AS(
                    j.apply(static_cast<void (json::array_t::*)(json::array_t::size_type, const json&)>(&json::array_t::resize), 2, json(42)),
                    "[json.exception.type_error.318] cannot invoke callable with JSON value of type array",
                    json::type_error&);
                CHECK(j.empty());
            }

            SECTION("non-const (with explicit placeholder)")
            {
                j.apply(static_cast<void (json::array_t::*)(json::array_t::size_type, const json&)>(&json::array_t::resize), json::value_placeholder, 2, json(42));

                CHECK(j == j_expected);
            }
        }

        SECTION("functor")
        {
            json j(42);

            SECTION("const (without explicit placeholder)")
            {
                functor f{0};
                const_(j).apply(f, -1, -2);

                CHECK(f.value == 42);
                CHECK(j == 42);
            }

            SECTION("const (with explicit placeholder)")
            {
                functor f{1};
                const_(j).apply(f, 0, json::value_placeholder, -2);

                CHECK(f.value == 42);
                CHECK(j == 42);
            }

            SECTION("non-const (without explicit placeholder)")
            {
                functor f{0};
                j.apply(f, -1, -2);

                CHECK(f.value == 42);
                CHECK(j == 42);
            }

            SECTION("non-const (with explicit placeholder)")
            {
                functor f{1};
                j.apply(f, 0, json::value_placeholder, -2);

                CHECK(f.value == 42);
                CHECK(j == 42);
            }
        }

        SECTION("discarded JSON value")
        {
            json j(json::value_t::discarded);

            SECTION("const")
            {
                CHECK_THROWS_WITH_AS(
                    const_(j).apply(nlohmann::detail::null_arg),
                    "[json.exception.type_error.318] cannot invoke callable with const JSON value of type discarded",
                    json::type_error&);
            }

            SECTION("non-const")
            {
                CHECK_THROWS_WITH_AS(
                    j.apply(nlohmann::detail::null_arg),
                    "[json.exception.type_error.318] cannot invoke callable with JSON value of type discarded",
                    json::type_error&);
            }
        }
    }

    SECTION("apply_r()")
    {
        SECTION("value types")
        {
            SECTION("null")
            {
                json j;

                auto is_null = [](std::nullptr_t) noexcept
                {
                    return true;
                };

                SECTION("const")
                {
                    CHECK(j.is_null());
                    CHECK(const_(j).apply_r<bool>(is_null));
                }

                SECTION("non-const")
                {
                    CHECK(j.is_null());
                    CHECK(j.apply_r<bool>(is_null));
                }
            }

            SECTION("object")
            {
                json j{{"foo", 0}, {"bar", 42}};

                auto get_bar = [](const json::object_t& obj)
                {
#if JSON_USE_IMPLICIT_CONVERSIONS
                    return obj.at("bar");
#else
                    return obj.at("bar").get<int>();
#endif
                };

                SECTION("const")
                {
                    CHECK(j.is_object());
                    CHECK(const_(j).apply_r<int>(get_bar) == 42);
                }

                SECTION("non-const")
                {
                    CHECK(j.is_object());
                    CHECK(j.apply_r<int>(get_bar) == 42);
                }
            }

            SECTION("array")
            {
                json j{0, 1, 42, 3, 4};

                auto get_2 = [](const json::array_t& arr)
                {
#if JSON_USE_IMPLICIT_CONVERSIONS
                    return arr[2];
#else
                    return arr[2].get<int>();
#endif
                };

                SECTION("const")
                {
                    CHECK(j.is_array());
                    CHECK(const_(j).apply_r<int>(get_2) == 42);
                }

                SECTION("non-const")
                {
                    CHECK(j.is_array());
                    CHECK(j.apply_r<int>(get_2) == 42);
                }
            }

            SECTION("string")
            {
                json j("fourty two");

                auto length = [](const json::string_t& str) noexcept
                {
                    return str.size();
                };

                SECTION("const")
                {
                    CHECK(j.is_string());
                    CHECK(const_(j).apply_r<std::size_t>(length) == 10);
                }

                SECTION("non-const")
                {
                    CHECK(j.is_string());
                    CHECK(j.apply_r<std::size_t>(length) == 10);
                }
            }

            SECTION("boolean")
            {
                json j(false);

                auto negate = [](bool b) noexcept
                {
                    return !b;
                };

                SECTION("const")
                {
                    CHECK(j.is_boolean());
                    CHECK(const_(j).apply_r<bool>(negate));
                }

                SECTION("non-const")
                {
                    CHECK(j.is_boolean());
                    CHECK(j.apply_r<bool>(negate));
                }
            }

            SECTION("number_integer")
            {
                json j(-7);

                auto calc = [](json::number_integer_t i) noexcept
                {
                    return i * i + i;
                };

                SECTION("const")
                {
                    CHECK(j.is_number_integer());
                    CHECK(const_(j).apply_r<int>(calc) == 42);
                }

                SECTION("non-const")
                {
                    CHECK(j.is_number_integer());
                    CHECK(j.apply_r<int>(calc) == 42);
                }
            }

            SECTION("number_unsigned")
            {
                json j(static_cast<json::number_unsigned_t>(7));

                auto calc = [](json::number_unsigned_t i) noexcept
                {
                    return i * i - i;
                };

                SECTION("const")
                {
                    CHECK(j.is_number_unsigned());
                    CHECK(const_(j).apply_r<int>(calc) == 42);
                }

                SECTION("non-const")
                {
                    CHECK(j.is_number_unsigned());
                    CHECK(j.apply_r<int>(calc) == 42);
                }
            }

            SECTION("number_float")
            {
                json j(6.480741);

                auto square = [](json::number_float_t f) noexcept
                {
                    return f * f;
                };

                SECTION("const")
                {
                    CHECK(j.is_number_float());
                    CHECK(const_(j).apply_r<double>(square) == doctest::Approx(42.0));
                }

                SECTION("non-const")
                {
                    CHECK(j.is_number_float());
                    CHECK(j.apply_r<double>(square) == doctest::Approx(42.0));
                }
            }

            SECTION("binary")
            {
                json j = json::binary(std::vector<std::uint8_t> {0xC0, 0xFF, 0xEE});

                auto get_1 = [](const json::binary_t& bin) noexcept
                {
                    return bin[1];
                };

                SECTION("const")
                {
                    CHECK(j.is_binary());
                    CHECK(const_(j).apply_r<std::uint8_t>(get_1) == 0xFF);
                }

                SECTION("non-const")
                {
                    CHECK(j.is_binary());
                    CHECK(j.apply_r<std::uint8_t>(get_1) == 0xFF);
                }
            }
        }

#if JSON_HAS_RANGES
        SECTION("std::ranges::min")
        {
            json j = json::array({5, 3, 4, 2});

            SECTION("const (without explicit placeholder)")
            {
                CHECK(const_(j).apply_r<int>(std::ranges::min) == 2);
            }

            SECTION("const (with explicit placeholder)")
            {
                CHECK(const_(j).apply_r<int>(std::ranges::min, json::value_placeholder) == 2);
            }

            SECTION("non-const (without explicit placeholder)")
            {
                CHECK(j.apply_r<int>(std::ranges::min) == 2);
            }

            SECTION("non-const (with explicit placeholder)")
            {
                CHECK(j.apply_r<int>(std::ranges::min, json::value_placeholder) == 2);
            }
        }
#endif
    }

    SECTION("apply_cb()")
    {
        SECTION("plain function callback")
        {
            json j(42);

            SECTION("const")
            {
                callback_value = 0;
                const_(j).apply_cb(callback, get_value);

                CHECK(callback_value == 42);
            }

            SECTION("non-const")
            {
                callback_value = 0;
                j.apply_cb(callback, get_value);

                CHECK(callback_value == 42);
            }

            SECTION("exception")
            {
                CHECK_THROWS_WITH_AS(
                    j.apply_cb(callback, get_not_an_int),
                    "[json.exception.type_error.319] cannot invoke callback",
                    json::type_error&);
            }
        }

        SECTION("static member function pointer")
        {
            json j(42);

            SECTION("const")
            {
                foo::static_bar = 0;
                const_(j).apply_cb(&foo::static_set_bar, get_value);

                CHECK(foo::static_bar == 42);
            }

            SECTION("non-const")
            {
                foo::static_bar = 0;
                j.apply_cb(&foo::static_set_bar, get_value);

                CHECK(foo::static_bar == 42);
            }
        }

        SECTION("non-static member function pointer")
        {
            json j(42);

            SECTION("const")
            {
                foo f;

                const_(j).apply_cb(&foo::set_bar, f, get_value);

                CHECK(f.bar == 42);
            }

            SECTION("non-const")
            {
                foo f;

                j.apply_cb(&foo::set_bar, f, get_value);

                CHECK(f.bar == 42);
            }
        }

        // add functor
    }
}

DOCTEST_CLANG_SUPPRESS_WARNING_POP
DOCTEST_GCC_SUPPRESS_WARNING_POP
DOCTEST_MSVC_SUPPRESS_WARNING_POP
