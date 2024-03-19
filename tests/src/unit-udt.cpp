//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.11.3
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2023 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

// disable -Wnoexcept due to class Evil
DOCTEST_GCC_SUPPRESS_WARNING_PUSH
DOCTEST_GCC_SUPPRESS_WARNING("-Wnoexcept")

#include <nlohmann/json.hpp>
using nlohmann::json;
#ifdef JSON_TEST_NO_GLOBAL_UDLS
    using namespace nlohmann::literals; // NOLINT(google-build-using-namespace)
#endif

#include <map>
#include <memory>
#include <string>
#include <utility>

namespace udt
{
enum class country
{
    china,
    france,
    russia
};

struct age
{
    int m_val;
    age(int rhs = 0) : m_val(rhs) {}
};

struct name
{
    std::string m_val;
    name(std::string rhs = "") : m_val(std::move(rhs)) {}
};

struct address
{
    std::string m_val;
    address(std::string rhs = "") : m_val(std::move(rhs)) {}
};

struct person
{
    age m_age{}; // NOLINT(readability-redundant-member-init)
    name m_name{}; // NOLINT(readability-redundant-member-init)
    country m_country{}; // NOLINT(readability-redundant-member-init)
    person() = default;
    person(const age& a, name  n, const country& c) : m_age(a), m_name(std::move(n)), m_country(c) {}
};

struct contact
{
    person m_person{}; // NOLINT(readability-redundant-member-init)
    address m_address{}; // NOLINT(readability-redundant-member-init)
    contact() = default;
    contact(person p, address a) : m_person(std::move(p)), m_address(std::move(a)) {}
};

enum class book_id : std::uint64_t;

struct contact_book
{
    name m_book_name{}; // NOLINT(readability-redundant-member-init)
    book_id m_book_id{};
    std::vector<contact> m_contacts{}; // NOLINT(readability-redundant-member-init)
    contact_book() = default;
    contact_book(name n, book_id i, std::vector<contact> c) : m_book_name(std::move(n)), m_book_id(i), m_contacts(std::move(c)) {}
};
} // namespace udt

// to_json methods
namespace udt
{
// templates because of the custom_json tests (see below)
template <typename BasicJsonType>
static void to_json(BasicJsonType& j, age a)
{
    j = a.m_val;
}

template <typename BasicJsonType>
static void to_json(BasicJsonType& j, const name& n)
{
    j = n.m_val;
}

template <typename BasicJsonType>
static void to_json(BasicJsonType& j, country c)
{
    switch (c)
    {
        case country::china:
            j = "中华人民共和国";
            return;
        case country::france:
            j = "France";
            return;
        case country::russia:
            j = "Российская Федерация";
            return;
        default:
            break;
    }
}

template <typename BasicJsonType>
static void to_json(BasicJsonType& j, const person& p)
{
    j = BasicJsonType{{"age", p.m_age}, {"name", p.m_name}, {"country", p.m_country}};
}

static void to_json(nlohmann::json& j, const address& a)
{
    j = a.m_val;
}

static void to_json(nlohmann::json& j, const contact& c)
{
    j = json{{"person", c.m_person}, {"address", c.m_address}};
}

static void to_json(nlohmann::json& j, const contact_book& cb)
{
    j = json{{"name", cb.m_book_name}, {"id", cb.m_book_id}, {"contacts", cb.m_contacts}};
}

// operators
static bool operator==(age lhs, age rhs)
{
    return lhs.m_val == rhs.m_val;
}

static bool operator==(const address& lhs, const address& rhs)
{
    return lhs.m_val == rhs.m_val;
}

static bool operator==(const name& lhs, const name& rhs)
{
    return lhs.m_val == rhs.m_val;
}

static bool operator==(const person& lhs, const person& rhs)
{
    return std::tie(lhs.m_name, lhs.m_age) == std::tie(rhs.m_name, rhs.m_age);
}

static bool operator==(const contact& lhs, const contact& rhs)
{
    return std::tie(lhs.m_person, lhs.m_address) ==
           std::tie(rhs.m_person, rhs.m_address);
}

static bool operator==(const contact_book& lhs, const contact_book& rhs)
{
    return std::tie(lhs.m_book_name, lhs.m_book_id, lhs.m_contacts) ==
           std::tie(rhs.m_book_name, rhs.m_book_id, rhs.m_contacts);
}
} // namespace udt

// from_json methods
namespace udt
{
template <typename BasicJsonType>
static void from_json(const BasicJsonType& j, age& a)
{
    a.m_val = j.template get<int>();
}

template <typename BasicJsonType>
static void from_json(const BasicJsonType& j, name& n)
{
    n.m_val = j.template get<std::string>();
}

template <typename BasicJsonType>
static void from_json(const BasicJsonType& j, country& c)
{
    const auto str = j.template get<std::string>();
    const std::map<std::string, country> m =
    {
        {"中华人民共和国", country::china},
        {"France", country::france},
        {"Российская Федерация", country::russia}
    };

    const auto it = m.find(str);
    // TODO(nlohmann) test exceptions
    c = it->second;
}

template <typename BasicJsonType>
static void from_json(const BasicJsonType& j, person& p)
{
    p.m_age = j["age"].template get<age>();
    p.m_name = j["name"].template get<name>();
    p.m_country = j["country"].template get<country>();
}

static void from_json(const nlohmann::json& j, address& a)
{
    a.m_val = j.get<std::string>();
}

static void from_json(const nlohmann::json& j, contact& c)
{
    c.m_person = j["person"].get<person>();
    c.m_address = j["address"].get<address>();
}

static void from_json(const nlohmann::json& j, contact_book& cb)
{
    cb.m_book_name = j["name"].get<name>();
    cb.m_book_id = j["id"].get<book_id>();
    cb.m_contacts = j["contacts"].get<std::vector<contact>>();
}
} // namespace udt

TEST_CASE("basic usage" * doctest::test_suite("udt"))
{

    // a bit narcissistic maybe :) ?
    const udt::age a
    {
        23
    };
    const udt::name n{"theo"};
    const udt::country c{udt::country::france};
    const udt::person sfinae_addict{a, n, c};
    const udt::person senior_programmer{{42}, {"王芳"}, udt::country::china};
    const udt::address addr{"Paris"};
    const udt::contact cpp_programmer{sfinae_addict, addr};
    const udt::book_id large_id{static_cast<udt::book_id>(static_cast<std::uint64_t>(1) << 63)}; // verify large unsigned enums are handled correctly
    const udt::contact_book book{{"C++"}, static_cast<udt::book_id>(42u), {cpp_programmer, {senior_programmer, addr}}};

    SECTION("conversion to json via free-functions")
    {
        CHECK(json(a) == json(23));
        CHECK(json(n) == json("theo"));
        CHECK(json(c) == json("France"));
        CHECK(json(sfinae_addict) == R"({"name":"theo", "age":23, "country":"France"})"_json);
        CHECK(json("Paris") == json(addr));
        CHECK(json(cpp_programmer) ==
              R"({"person" : {"age":23, "name":"theo", "country":"France"}, "address":"Paris"})"_json);
        CHECK(json(large_id) == json(static_cast<std::uint64_t>(1) << 63));
        CHECK(json(large_id) > 0u);
        CHECK(to_string(json(large_id)) == "9223372036854775808");
        CHECK(json(large_id).is_number_unsigned());

        CHECK(
            json(book) ==
            R"({"name":"C++", "id":42, "contacts" : [{"person" : {"age":23, "name":"theo", "country":"France"}, "address":"Paris"}, {"person" : {"age":42, "country":"中华人民共和国", "name":"王芳"}, "address":"Paris"}]})"_json);

    }

    SECTION("conversion from json via free-functions")
    {
        const auto big_json =
            R"({"name":"C++", "id":42, "contacts" : [{"person" : {"age":23, "name":"theo", "country":"France"}, "address":"Paris"}, {"person" : {"age":42, "country":"中华人民共和国", "name":"王芳"}, "address":"Paris"}]})"_json;
        SECTION("via explicit calls to get")
        {
            const auto parsed_book = big_json.get<udt::contact_book>();
            const auto book_name = big_json["name"].get<udt::name>();
            const auto book_id = big_json["id"].get<udt::book_id>();
            const auto contacts =
                big_json["contacts"].get<std::vector<udt::contact>>();
            const auto contact_json = big_json["contacts"].at(0);
            const auto contact = contact_json.get<udt::contact>();
            const auto person = contact_json["person"].get<udt::person>();
            const auto address = contact_json["address"].get<udt::address>();
            const auto age = contact_json["person"]["age"].get<udt::age>();
            const auto country =
                contact_json["person"]["country"].get<udt::country>();
            const auto name = contact_json["person"]["name"].get<udt::name>();

            CHECK(age == a);
            CHECK(name == n);
            CHECK(country == c);
            CHECK(address == addr);
            CHECK(person == sfinae_addict);
            CHECK(contact == cpp_programmer);
            CHECK(contacts == book.m_contacts);
            CHECK(book_name == udt::name{"C++"});
            CHECK(book_id == book.m_book_id);
            CHECK(book == parsed_book);
        }

        SECTION("via explicit calls to get_to")
        {
            udt::person person;
            udt::name name;

            json person_json = big_json["contacts"][0]["person"];
            CHECK(person_json.get_to(person) == sfinae_addict);

            // correct reference gets returned
            person_json["name"].get_to(name).m_val = "new name";
            CHECK(name.m_val == "new name");
        }

#if JSON_USE_IMPLICIT_CONVERSIONS
        SECTION("implicit conversions")
        {
            const udt::contact_book parsed_book = big_json;
            const udt::name book_name = big_json["name"];
            const udt::book_id book_id = big_json["id"];
            const std::vector<udt::contact> contacts = big_json["contacts"];
            const auto contact_json = big_json["contacts"].at(0);
            const udt::contact contact = contact_json;
            const udt::person person = contact_json["person"];
            const udt::address address = contact_json["address"];
            const udt::age age = contact_json["person"]["age"];
            const udt::country country = contact_json["person"]["country"];
            const udt::name name = contact_json["person"]["name"];

            CHECK(age == a);
            CHECK(name == n);
            CHECK(country == c);
            CHECK(address == addr);
            CHECK(person == sfinae_addict);
            CHECK(contact == cpp_programmer);
            CHECK(contacts == book.m_contacts);
            CHECK(book_name == udt::name{"C++"});
            CHECK(book_id == static_cast<udt::book_id>(42u));
            CHECK(book == parsed_book);
        }
#endif
    }
}

namespace udt
{
struct legacy_type
{
    std::string number{}; // NOLINT(readability-redundant-member-init)
    legacy_type() = default;
    legacy_type(std::string n) : number(std::move(n)) {}
};
} // namespace udt

namespace nlohmann
{
template <typename T>
struct adl_serializer<std::shared_ptr<T>>
{
    static void to_json(json& j, const std::shared_ptr<T>& opt)
    {
        if (opt)
        {
            j = *opt;
        }
        else
        {
            j = nullptr;
        }
    }

    static void from_json(const json& j, std::shared_ptr<T>& opt)
    {
        if (j.is_null())
        {
            opt = nullptr;
        }
        else
        {
            opt.reset(new T(j.get<T>())); // NOLINT(cppcoreguidelines-owning-memory)
        }
    }
};

template <>
struct adl_serializer<udt::legacy_type>
{
    static void to_json(json& j, const udt::legacy_type& l)
    {
        j = std::stoi(l.number);
    }

    static void from_json(const json& j, udt::legacy_type& l)
    {
        l.number = std::to_string(j.get<int>());
    }
};
} // namespace nlohmann

TEST_CASE("adl_serializer specialization" * doctest::test_suite("udt"))
{
    SECTION("partial specialization")
    {
        SECTION("to_json")
        {
            std::shared_ptr<udt::person> optPerson;

            json j = optPerson;
            CHECK(j.is_null());

            optPerson.reset(new udt::person{{42}, {"John Doe"}, udt::country::russia}); // NOLINT(cppcoreguidelines-owning-memory,modernize-make-shared)
            j = optPerson;
            CHECK_FALSE(j.is_null());

            CHECK(j.get<udt::person>() == *optPerson);
        }

        SECTION("from_json")
        {
            auto person = udt::person{{42}, {"John Doe"}, udt::country::russia};
            json j = person;

            auto optPerson = j.get<std::shared_ptr<udt::person>>();
            REQUIRE(optPerson);
            CHECK(*optPerson == person);

            j = nullptr;
            optPerson = j.get<std::shared_ptr<udt::person>>();
            CHECK(!optPerson);
        }
    }

    SECTION("total specialization")
    {
        SECTION("to_json")
        {
            udt::legacy_type const lt{"4242"};

            json const j = lt;
            CHECK(j.get<int>() == 4242);
        }

        SECTION("from_json")
        {
            json const j = 4242;
            auto lt = j.get<udt::legacy_type>();
            CHECK(lt.number == "4242");
        }
    }
}

namespace nlohmann
{
template <>
struct adl_serializer<std::vector<float>>
{
    using type = std::vector<float>;
    static void to_json(json& j, const type& /*type*/)
    {
        j = "hijacked!";
    }

    static void from_json(const json& /*unnamed*/, type& opt)
    {
        opt = {42.0, 42.0, 42.0};
    }

    // preferred version
    static type from_json(const json& /*unnamed*/)
    {
        return {4.0, 5.0, 6.0};
    }
};
} // namespace nlohmann

TEST_CASE("even supported types can be specialized" * doctest::test_suite("udt"))
{
    json const j = std::vector<float> {1.0, 2.0, 3.0};
    CHECK(j.dump() == R"("hijacked!")");
    auto f = j.get<std::vector<float>>();
    // the single argument from_json method is preferred
    CHECK((f == std::vector<float> {4.0, 5.0, 6.0}));
}

namespace nlohmann
{
template <typename T>
struct adl_serializer<std::unique_ptr<T>>
{
    static void to_json(json& j, const std::unique_ptr<T>& opt)
    {
        if (opt)
        {
            j = *opt;
        }
        else
        {
            j = nullptr;
        }
    }

    // this is the overload needed for non-copyable types,
    static std::unique_ptr<T> from_json(const json& j)
    {
        if (j.is_null())
        {
            return nullptr;
        }

        return std::unique_ptr<T>(new T(j.get<T>()));
    }
};
} // namespace nlohmann

TEST_CASE("Non-copyable types" * doctest::test_suite("udt"))
{
    SECTION("to_json")
    {
        std::unique_ptr<udt::person> optPerson;

        json j = optPerson;
        CHECK(j.is_null());

        optPerson.reset(new udt::person{{42}, {"John Doe"}, udt::country::russia}); // NOLINT(cppcoreguidelines-owning-memory,modernize-make-unique)
        j = optPerson;
        CHECK_FALSE(j.is_null());

        CHECK(j.get<udt::person>() == *optPerson);
    }

    SECTION("from_json")
    {
        auto person = udt::person{{42}, {"John Doe"}, udt::country::russia};
        json j = person;

        auto optPerson = j.get<std::unique_ptr<udt::person>>();
        REQUIRE(optPerson);
        CHECK(*optPerson == person);

        j = nullptr;
        optPerson = j.get<std::unique_ptr<udt::person>>();
        CHECK(!optPerson);
    }
}

// custom serializer - advanced usage
// pack structs that are pod-types (but not scalar types)
// relies on adl for any other type
template <typename T, typename = void>
struct pod_serializer
{
    // use adl for non-pods, or scalar types
    template <
        typename BasicJsonType, typename U = T,
        typename std::enable_if <
            !(std::is_pod<U>::value && std::is_class<U>::value), int >::type = 0 >
    static void from_json(const BasicJsonType& j, U& t)
    {
        using nlohmann::from_json;
        from_json(j, t);
    }

    // special behaviour for pods
    template < typename BasicJsonType, typename U = T,
               typename std::enable_if <
                   std::is_pod<U>::value && std::is_class<U>::value, int >::type = 0 >
    static void from_json(const  BasicJsonType& j, U& t)
    {
        std::uint64_t value = 0;
        // The following block is no longer relevant in this serializer, make another one that shows the issue
        // the problem arises only when one from_json method is defined without any constraint
        //
        // Why cannot we simply use: j.get<std::uint64_t>() ?
        // Well, with the current experiment, the get method looks for a from_json
        // function, which we are currently defining!
        // This would end up in a stack overflow. Calling nlohmann::from_json is a
        // workaround (is it?).
        // I shall find a good way to avoid this once all constructors are converted
        // to free methods
        //
        // In short, constructing a json by constructor calls to_json
        // calling get calls from_json, for now, we cannot do this in custom
        // serializers
        nlohmann::from_json(j, value);
        auto* bytes = static_cast<char*>(static_cast<void*>(&value)); // NOLINT(bugprone-casting-through-void)
        std::memcpy(&t, bytes, sizeof(value));
    }

    template <
        typename BasicJsonType, typename U = T,
        typename std::enable_if <
            !(std::is_pod<U>::value && std::is_class<U>::value), int >::type = 0 >
    static void to_json(BasicJsonType& j, const  T& t)
    {
        using nlohmann::to_json;
        to_json(j, t);
    }

    template < typename BasicJsonType, typename U = T,
               typename std::enable_if <
                   std::is_pod<U>::value && std::is_class<U>::value, int >::type = 0 >
    static void to_json(BasicJsonType& j, const  T& t) noexcept
    {
        const auto* bytes = static_cast< const unsigned char*>(static_cast<const void*>(&t));  // NOLINT(bugprone-casting-through-void)
        std::uint64_t value = 0;
        std::memcpy(&value, bytes, sizeof(value));
        nlohmann::to_json(j, value);
    }
};

namespace udt
{
struct small_pod
{
    int begin;
    char middle;
    short end;
};

struct non_pod
{
    std::string s{}; // NOLINT(readability-redundant-member-init)
    non_pod() = default;
    non_pod(std::string S) : s(std::move(S)) {}
};

template <typename BasicJsonType>
static void to_json(BasicJsonType& j, const non_pod& np)
{
    j = np.s;
}

template <typename BasicJsonType>
static void from_json(const BasicJsonType& j, non_pod& np)
{
    np.s = j.template get<std::string>();
}

static bool operator==(small_pod lhs, small_pod rhs) noexcept
{
    return std::tie(lhs.begin, lhs.middle, lhs.end) ==
           std::tie(rhs.begin, rhs.middle, rhs.end);
}

static bool operator==(const  non_pod& lhs, const  non_pod& rhs) noexcept
{
    return lhs.s == rhs.s;
}

static std::ostream& operator<<(std::ostream& os, small_pod l)
{
    return os << "begin: " << l.begin << ", middle: " << l.middle << ", end: " << l.end;
}
} // namespace udt

TEST_CASE("custom serializer for pods" * doctest::test_suite("udt"))
{
    using custom_json =
        nlohmann::json::with_changed_json_serializer_t<pod_serializer>;

    auto p = udt::small_pod{42, '/', 42};
    custom_json const j = p;

    auto p2 = j.get<udt::small_pod>();

    CHECK(p == p2);

    auto np = udt::non_pod{{"non-pod"}};
    custom_json const j2 = np;
    auto np2 = j2.get<udt::non_pod>();
    CHECK(np == np2);
}

template <typename T, typename>
struct another_adl_serializer;

using custom_json = nlohmann::json::with_changed_json_serializer_t<another_adl_serializer>;

template <typename T, typename>
struct another_adl_serializer
{
    static void from_json(const custom_json& j, T& t)
    {
        using nlohmann::from_json;
        from_json(j, t);
    }

    static void to_json(custom_json& j, const T& t)
    {
        using nlohmann::to_json;
        to_json(j, t);
    }
};

TEST_CASE("custom serializer that does adl by default" * doctest::test_suite("udt"))
{
    auto me = udt::person{{23}, {"theo"}, udt::country::france};

    json const j = me;
    custom_json const cj = me;

    CHECK(j.dump() == cj.dump());

    CHECK(me == j.get<udt::person>());
    CHECK(me == cj.get<udt::person>());
}

TEST_CASE("different basic_json types conversions")
{
    SECTION("null")
    {
        json const j;
        custom_json cj = j;
        CHECK(cj == nullptr);
    }

    SECTION("boolean")
    {
        json const j = true;
        custom_json cj = j;
        CHECK(cj == true);
    }

    SECTION("discarded")
    {
        json const j(json::value_t::discarded);
        custom_json cj;
        CHECK_NOTHROW(cj = j);
        CHECK(cj.type() == custom_json::value_t::discarded);
    }

    SECTION("array")
    {
        json const j = {1, 2, 3};
        custom_json const cj = j;
        CHECK((cj == std::vector<int> {1, 2, 3}));
    }

    SECTION("integer")
    {
        json const j = 42;
        custom_json cj = j;
        CHECK(cj == 42);
    }

    SECTION("float")
    {
        json const j = 42.0;
        custom_json cj = j;
        CHECK(cj == 42.0);
    }

    SECTION("unsigned")
    {
        json const j = 42u;
        custom_json cj = j;
        CHECK(cj == 42u);
    }

    SECTION("string")
    {
        json const j = "forty-two";
        custom_json cj = j;
        CHECK(cj == "forty-two");
    }

    SECTION("binary")
    {
        json j = json::binary({1, 2, 3}, 42);
        custom_json cj = j;
        CHECK(cj.get_binary().subtype() == 42);
        std::vector<std::uint8_t> cv = cj.get_binary();
        std::vector<std::uint8_t> v = j.get_binary();
        CHECK(cv == v);
    }

    SECTION("object")
    {
        json const j = {{"forty", "two"}};
        custom_json cj = j;
        auto m = j.get<std::map<std::string, std::string>>();
        CHECK(cj == m);
    }

    SECTION("get<custom_json>")
    {
        json const j = 42;
        custom_json cj = j.get<custom_json>();
        CHECK(cj == 42);
    }
}

namespace
{
struct incomplete;

// std::is_constructible is broken on macOS' libc++
// use the cppreference implementation

template <typename T, typename = void>
struct is_constructible_patched : std::false_type {};

template <typename T>
struct is_constructible_patched<T, decltype(void(json(std::declval<T>())))> : std::true_type {};
} // namespace

TEST_CASE("an incomplete type does not trigger a compiler error in non-evaluated context" * doctest::test_suite("udt"))
{
    static_assert(!is_constructible_patched<json, incomplete>::value, "");
}

namespace
{
class Evil
{
  public:
    Evil() = default;
    template <typename T>
    Evil(T t) : m_i(sizeof(t))
    {
        static_cast<void>(t); // fix MSVC's C4100 warning
    }

    int m_i = 0;
};

void from_json(const json& /*unused*/, Evil& /*unused*/) {}
} // namespace

TEST_CASE("Issue #924")
{
    // Prevent get<std::vector<Evil>>() to throw
    auto j = json::array();

    CHECK_NOTHROW(j.get<Evil>());
    CHECK_NOTHROW(j.get<std::vector<Evil>>());

    // silence Wunused-template warnings
    Evil e(1);
    CHECK(e.m_i >= 0);
}

TEST_CASE("Issue #1237")
{
    struct non_convertible_type {};
    static_assert(!std::is_convertible<json, non_convertible_type>::value, "");
}

namespace
{
class no_iterator_type
{
  public:
    no_iterator_type(std::initializer_list<int> l)
        : _v(l)
    {}

    std::vector<int>::const_iterator begin() const
    {
        return _v.begin();
    }

    std::vector<int>::const_iterator end() const
    {
        return _v.end();
    }

  private:
    std::vector<int> _v;
};
}  // namespace

TEST_CASE("compatible array type, without iterator type alias")
{
    no_iterator_type const vec{1, 2, 3};
    json const j = vec;
}

DOCTEST_GCC_SUPPRESS_WARNING_POP
