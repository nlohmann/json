//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>

#if JSON_HAS_REFLECTION
#include <optional>
#include <string>
#include <vector>

using nlohmann::json;

// The sample user types below are plain data holders. -Weffc++ wants every
// member listed in a member-initializer list even when a default member
// initializer or the implicit default constructor is exactly what is intended;
// that rule is noise for these aggregates, so it is suppressed around them.
DOCTEST_GCC_SUPPRESS_WARNING_PUSH
DOCTEST_GCC_SUPPRESS_WARNING("-Weffc++")

namespace
{

enum class Element
{
    FIRE,
    WATER,
    EARTH,
    WIND,
};

struct Spell
{
    std::string name;
    int cost = 0;
    Element element = Element::FIRE;
};

struct Player
{
    [[ = nlohmann::rename("full_name")]] std::string name;
    int bombs = 3;
    std::optional<int> graze;
    std::vector<Spell> spells;
    [[ = nlohmann::transient]] std::string password;
};

struct Metadata
{
    std::string author;
    int version = 1;
};

struct Document
{
    std::string title;
    [[ = nlohmann::flatten]] Metadata info;
};

class [[ = nlohmann::reflectable]] Account
{
  private:
    std::string owner;
    long balance = 0;

  public:
    Account() = default;
    Account(std::string owner_, long balance_):
        owner{std::move(owner_)}, balance{balance_} {}

    [[nodiscard]]
    const std::string& who() const noexcept
    {
        return owner;
    }

    [[nodiscard]]
    long amount() const noexcept
    {
        return balance;
    }
};

}  // namespace

TEST_CASE("reflection serde")
{
    SECTION("serialize a plain struct")
    {
        const Player reimu =
        {
            .name = "Reimu Hakurei",
            .bombs = 5,
            .graze = 30,
            .spells = {
                Spell {.name = "Fantasy Seal", .cost = 50, .element = Element::WIND},
                Spell {.name = "Evil-Sealing Circle", .cost = 20, .element = Element::FIRE},
            },
            .password = "never persist me",
        };

        const json j = json::serialize(reimu);

        CHECK(j.is_object());
        CHECK(j.contains("full_name")); // rename
        CHECK_FALSE(j.contains("name")); // original name unused
        CHECK_FALSE(j.contains("password")); // transient omitted
        CHECK(j.at("full_name") == "Reimu Hakurei");
        CHECK(j.at("bombs") == 5);
        CHECK(j.at("graze") == 30);
        CHECK(j.at("spells").size() == 2);
        CHECK(j.at("spells").at(0).at("element") == "WIND"); // enum by name
    }

    SECTION("round-trip a plain struct")
    {
        const Player reimu =
        {
            .name = "Reimu Hakurei",
            .bombs = 5,
            .graze = 30,
            .spells = { Spell {.name = "Fantasy Seal", .cost = 50, .element = Element::WIND} },
            .password = "secret",
        };

        const Player back = json::serialize(reimu).deserialize<Player>();

        CHECK(back.name == "Reimu Hakurei"); // renamed key read back
        CHECK(back.bombs == 5);
        REQUIRE(back.graze.has_value());
        CHECK(*back.graze == 30);
        REQUIRE(back.spells.size() == 1);
        CHECK(back.spells[0].element == Element::WIND);
        CHECK(back.password.empty()); // transient stays default
    }

    SECTION("optional members")
    {
        // graze has no initializer, so a default-constructed Player leaves it empty
        Player marisa;
        marisa.name = "Marisa Kirisame";

        // empty optional serializes to null
        CHECK(json::serialize(marisa).at("graze").is_null());

        // a missing key leaves the optional empty, not an error
        const Player none = json::parse(R"({"full_name":"Marisa Kirisame","bombs":2})").deserialize<Player>();
        CHECK(none.name == "Marisa Kirisame");
        CHECK(none.bombs == 2);
        CHECK_FALSE(none.graze.has_value());
        CHECK(none.spells.empty());

        // an explicit null also yields an empty optional
        const Player null_mana = json::parse(R"({"full_name":"Alice Margatroid","bombs":4,"graze":null})").deserialize<Player>();
        CHECK_FALSE(null_mana.graze.has_value());
    }

    SECTION("flatten inlines a nested struct")
    {
        const Document doc =
        {
            .title = "The Grimore of Marisa",
            .info = Metadata {
                .author = "Marisa Kirisame",
                .version = 3,
            }
        };
        const json j = json::serialize(doc);

        CHECK(j.contains("title"));
        CHECK(j.contains("author")); // inlined
        CHECK(j.contains("version")); // inlined
        CHECK_FALSE(j.contains("info")); // no nesting key

        const Document back = j.deserialize<Document>();
        CHECK(back.title == "The Grimore of Marisa");
        CHECK(back.info.author == "Marisa Kirisame");
        CHECK(back.info.version == 3);
    }

    SECTION("reflectable reaches private members")
    {
        const Account acc("Sakuya Izayoi", 100);
        const json j = json::serialize(acc);

        CHECK(j.at("owner") == "Sakuya Izayoi");
        CHECK(j.at("balance") == 100);

        const Account back = j.deserialize<Account>();
        CHECK(back.who() == "Sakuya Izayoi");
        CHECK(back.amount() == 100);
    }

    SECTION("unknown enumerator name throws deserialization_error")
    {
        const json j = json::parse(R"({"name":"x","cost":1,"element":"PLASMA"})");
        CHECK_THROWS_AS([&] -> const Spell { const Spell s = j.deserialize<Spell>(); return s; }(),
                        json::exception);
    }
}

DOCTEST_GCC_SUPPRESS_WARNING_POP

#else

TEST_CASE("reflection serde is unavailable on this toolchain")
{
    CHECK(JSON_HAS_REFLECTION == 0);
}

#endif
