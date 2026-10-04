//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"
#include "test_utils.hpp"

#include <nlohmann/json.hpp>
using nlohmann::json;

#include <string>
#include <vector>

namespace
{

struct ill_formed_case
{
    const char* name;
    std::string bytes;
};

// RFC 3629 ill-formed sequences used throughout this file, plus one
// well-formed sequence for contrast
std::vector<ill_formed_case> ill_formed_cases()
{
    return
    {
        {"overlong", "\xC0\xAE"},
        {"lone_0xFF", "\xFF"},
        {"truncated", "\xE2\x82"},
        {"surrogate", "\xED\xA0\x80"},
    };
}

std::string valid_sequence()
{
    return "\xC3\xA9"; // U+00E9, "é"
}

using eh = json::error_handler_t;
std::vector<eh> all_handlers()
{
    return {eh::strict, eh::replace, eh::ignore, eh::keep};
}

// what dump()+parse() produces for a sanitizing error_handler; this is the
// ground truth every binary writer/reader is checked against
std::string dump_and_parse(const std::string& raw, eh error_handler)
{
    return json::parse(json(raw).dump(-1, ' ', false, error_handler)).get<std::string>();
}

} // namespace

TEST_CASE("UTF-8 error_handler for the binary readers and writers")
{
    SECTION("writers: string value")
    {
        for (const auto& c : ill_formed_cases())
        {
            CAPTURE(c.name)
            const json jval = c.bytes;

            CHECK_THROWS_AS(json::to_cbor(jval, eh::strict), json::type_error&);
            CHECK_THROWS_AS(json::to_msgpack(jval, eh::strict), json::type_error&);
            CHECK_THROWS_AS(json::to_ubjson(jval, false, false, eh::strict), json::type_error&);
            CHECK_THROWS_AS(json::to_bjdata(jval, false, false, json::bjdata_version_t::draft2, eh::strict), json::type_error&);
            {
                json jobj;
                jobj["k"] = jval;
                CHECK_THROWS_AS(json::to_bson(jobj, eh::strict), json::type_error&);
            }

            for (const auto h :
                    {
                        eh::replace, eh::ignore
                    })
            {
                CAPTURE(static_cast<int>(h))
                const std::string expected = dump_and_parse(c.bytes, h);

                CHECK(json::from_cbor(json::to_cbor(jval, h)).get<std::string>() == expected);
                CHECK(json::from_msgpack(json::to_msgpack(jval, h)).get<std::string>() == expected);
                CHECK(json::from_ubjson(json::to_ubjson(jval, false, false, h)).get<std::string>() == expected);
                CHECK(json::from_bjdata(json::to_bjdata(jval, false, false, json::bjdata_version_t::draft2, h)).get<std::string>() == expected);
                {
                    json jobj;
                    jobj["k"] = jval;
                    const auto bytes = json::to_bson(jobj, h);
                    CHECK(json::from_bson(bytes)["k"].get<std::string>() == expected);
                }
            }

            // keep: the writer passes the ill-formed bytes through unchanged,
            // exactly as every binary writer did before this parameter existed
            CHECK(json::from_cbor(json::to_cbor(jval, eh::keep)).get<std::string>() == c.bytes);
            CHECK(json::from_msgpack(json::to_msgpack(jval, eh::keep)).get<std::string>() == c.bytes);
            CHECK(json::from_ubjson(json::to_ubjson(jval, false, false, eh::keep)).get<std::string>() == c.bytes);
            CHECK(json::from_bjdata(json::to_bjdata(jval, false, false, json::bjdata_version_t::draft2, eh::keep)).get<std::string>() == c.bytes);
            {
                json jobj;
                jobj["k"] = jval;
                const auto bytes = json::to_bson(jobj, eh::keep);
                CHECK(json::from_bson(bytes)["k"].get<std::string>() == c.bytes);
            }
        }
    }

    SECTION("writers: object key")
    {
        for (const auto& c : ill_formed_cases())
        {
            CAPTURE(c.name)
            json jobj;
            jobj[c.bytes] = 1;

            CHECK_THROWS_AS(json::to_cbor(jobj, eh::strict), json::type_error&);
            CHECK_THROWS_AS(json::to_msgpack(jobj, eh::strict), json::type_error&);
            CHECK_THROWS_AS(json::to_ubjson(jobj, false, false, eh::strict), json::type_error&);
            CHECK_THROWS_AS(json::to_bjdata(jobj, false, false, json::bjdata_version_t::draft2, eh::strict), json::type_error&);
            CHECK_THROWS_AS(json::to_bson(jobj, eh::strict), json::type_error&);

            for (const auto h :
                    {
                        eh::replace, eh::ignore
                    })
            {
                CAPTURE(static_cast<int>(h))
                const std::string expected = dump_and_parse(c.bytes, h);

                CHECK(json::from_cbor(json::to_cbor(jobj, h)).begin().key() == expected);
                CHECK(json::from_msgpack(json::to_msgpack(jobj, h)).begin().key() == expected);
                CHECK(json::from_ubjson(json::to_ubjson(jobj, false, false, h)).begin().key() == expected);
                CHECK(json::from_bjdata(json::to_bjdata(jobj, false, false, json::bjdata_version_t::draft2, h)).begin().key() == expected);
                CHECK(json::from_bson(json::to_bson(jobj, h)).begin().key() == expected);
            }

            // keep: object keys round-trip unchanged too
            CHECK(json::from_cbor(json::to_cbor(jobj, eh::keep)).begin().key() == c.bytes);
            CHECK(json::from_msgpack(json::to_msgpack(jobj, eh::keep)).begin().key() == c.bytes);
            CHECK(json::from_ubjson(json::to_ubjson(jobj, false, false, eh::keep)).begin().key() == c.bytes);
            CHECK(json::from_bjdata(json::to_bjdata(jobj, false, false, json::bjdata_version_t::draft2, eh::keep)).begin().key() == c.bytes);
            CHECK(json::from_bson(json::to_bson(jobj, eh::keep)).begin().key() == c.bytes);
        }
    }

    SECTION("readers: string value")
    {
        for (const auto& c : ill_formed_cases())
        {
            CAPTURE(c.name)

            // bytes produced the lenient (keep) way, as any binary reader
            // accepted them before this parameter existed
            const auto cbor_bytes = json::to_cbor(json(c.bytes), eh::keep);
            const auto msgpack_bytes = json::to_msgpack(json(c.bytes)); // to_msgpack has no error_handler; always pass-through
            const auto ubjson_bytes = json::to_ubjson(json(c.bytes), false, false, eh::keep);
            const auto bjdata_bytes = json::to_bjdata(json(c.bytes), false, false, json::bjdata_version_t::draft2, eh::keep);
            const auto bson_bytes = [&c]
            {
                json jobj;
                jobj["k"] = c.bytes;
                return json::to_bson(jobj, eh::keep);
            }();

            // keep (the default): bytes are kept unchanged
            CHECK(json::from_cbor(cbor_bytes).get<std::string>() == c.bytes);
            CHECK(json::from_msgpack(msgpack_bytes).get<std::string>() == c.bytes);
            CHECK(json::from_ubjson(ubjson_bytes).get<std::string>() == c.bytes);
            CHECK(json::from_bjdata(bjdata_bytes).get<std::string>() == c.bytes);
            CHECK(json::from_bson(bson_bytes)["k"].get<std::string>() == c.bytes);

            // strict: parse_error.113, discarded (not thrown) when allow_exceptions is false
            CHECK_THROWS_AS(utils::ignore_return_value(json::from_cbor(cbor_bytes, true, true, json::cbor_tag_handler_t::error, eh::strict)), json::parse_error&);
            CHECK(json::from_cbor(cbor_bytes, true, false, json::cbor_tag_handler_t::error, eh::strict).is_discarded());
            CHECK_THROWS_AS(utils::ignore_return_value(json::from_msgpack(msgpack_bytes, true, true, eh::strict)), json::parse_error&);
            CHECK(json::from_msgpack(msgpack_bytes, true, false, eh::strict).is_discarded());
            CHECK_THROWS_AS(utils::ignore_return_value(json::from_ubjson(ubjson_bytes, true, true, eh::strict)), json::parse_error&);
            CHECK(json::from_ubjson(ubjson_bytes, true, false, eh::strict).is_discarded());
            CHECK_THROWS_AS(utils::ignore_return_value(json::from_bjdata(bjdata_bytes, true, true, eh::strict)), json::parse_error&);
            CHECK(json::from_bjdata(bjdata_bytes, true, false, eh::strict).is_discarded());
            CHECK_THROWS_AS(utils::ignore_return_value(json::from_bson(bson_bytes, true, true, eh::strict)), json::parse_error&);
            CHECK(json::from_bson(bson_bytes, true, false, eh::strict).is_discarded());

            // replace / ignore: match what dump() would have sanitized the same bytes to
            for (const auto h :
                    {
                        eh::replace, eh::ignore
                    })
            {
                CAPTURE(static_cast<int>(h))
                const std::string expected = dump_and_parse(c.bytes, h);

                CHECK(json::from_cbor(cbor_bytes, true, true, json::cbor_tag_handler_t::error, h).get<std::string>() == expected);
                CHECK(json::from_msgpack(msgpack_bytes, true, true, h).get<std::string>() == expected);
                CHECK(json::from_ubjson(ubjson_bytes, true, true, h).get<std::string>() == expected);
                CHECK(json::from_bjdata(bjdata_bytes, true, true, h).get<std::string>() == expected);
                CHECK(json::from_bson(bson_bytes, true, true, h)["k"].get<std::string>() == expected);
            }
        }
    }

    SECTION("readers: object key")
    {
        for (const auto& c : ill_formed_cases())
        {
            CAPTURE(c.name)

            json jobj;
            jobj[c.bytes] = 1;
            const auto cbor_bytes = json::to_cbor(jobj, eh::keep);
            const auto msgpack_bytes = json::to_msgpack(jobj);
            const auto ubjson_bytes = json::to_ubjson(jobj, false, false, eh::keep);
            const auto bjdata_bytes = json::to_bjdata(jobj, false, false, json::bjdata_version_t::draft2, eh::keep);
            const auto bson_bytes = json::to_bson(jobj, eh::keep);

            CHECK(json::from_cbor(cbor_bytes).begin().key() == c.bytes);
            CHECK(json::from_msgpack(msgpack_bytes).begin().key() == c.bytes);
            CHECK(json::from_ubjson(ubjson_bytes).begin().key() == c.bytes);
            CHECK(json::from_bjdata(bjdata_bytes).begin().key() == c.bytes);
            CHECK(json::from_bson(bson_bytes).begin().key() == c.bytes);

            CHECK_THROWS_AS(utils::ignore_return_value(json::from_cbor(cbor_bytes, true, true, json::cbor_tag_handler_t::error, eh::strict)), json::parse_error&);
            CHECK_THROWS_AS(utils::ignore_return_value(json::from_msgpack(msgpack_bytes, true, true, eh::strict)), json::parse_error&);
            CHECK_THROWS_AS(utils::ignore_return_value(json::from_ubjson(ubjson_bytes, true, true, eh::strict)), json::parse_error&);
            CHECK_THROWS_AS(utils::ignore_return_value(json::from_bjdata(bjdata_bytes, true, true, eh::strict)), json::parse_error&);
            CHECK_THROWS_AS(utils::ignore_return_value(json::from_bson(bson_bytes, true, true, eh::strict)), json::parse_error&);

            for (const auto h :
                    {
                        eh::replace, eh::ignore
                    })
            {
                CAPTURE(static_cast<int>(h))
                const std::string expected = dump_and_parse(c.bytes, h);

                CHECK(json::from_cbor(cbor_bytes, true, true, json::cbor_tag_handler_t::error, h).begin().key() == expected);
                CHECK(json::from_msgpack(msgpack_bytes, true, true, h).begin().key() == expected);
                CHECK(json::from_ubjson(ubjson_bytes, true, true, h).begin().key() == expected);
                CHECK(json::from_bjdata(bjdata_bytes, true, true, h).begin().key() == expected);
                CHECK(json::from_bson(bson_bytes, true, true, h).begin().key() == expected);
            }
        }
    }

    SECTION("well-formed UTF-8 is unaffected by error_handler")
    {
        const json jval = valid_sequence();
        json jobj;
        jobj[valid_sequence()] = valid_sequence();

        for (const auto h : all_handlers())
        {
            CAPTURE(static_cast<int>(h))

            CHECK(json::from_cbor(json::to_cbor(jval, h)).get<std::string>() == valid_sequence());
            CHECK(json::from_msgpack(json::to_msgpack(jval, h)).get<std::string>() == valid_sequence());
            CHECK(json::from_ubjson(json::to_ubjson(jval, false, false, h)).get<std::string>() == valid_sequence());
            CHECK(json::from_bjdata(json::to_bjdata(jval, false, false, json::bjdata_version_t::draft2, h)).get<std::string>() == valid_sequence());
            CHECK(json::from_bson(json::to_bson(jobj, h)).begin().key() == valid_sequence());

            CHECK(json::from_cbor(json::to_cbor(jval, eh::keep), true, true, json::cbor_tag_handler_t::error, h).get<std::string>() == valid_sequence());
            CHECK(json::from_msgpack(json::to_msgpack(jval), true, true, h).get<std::string>() == valid_sequence());
        }
    }

    SECTION("dump() with error_handler_t::keep writes raw bytes as is")
    {
        for (const auto& c : ill_formed_cases())
        {
            CAPTURE(c.name)

            const json jval = c.bytes;
            const std::string dumped = jval.dump(-1, ' ', false, eh::keep);
            CHECK(dumped.find(c.bytes) != std::string::npos);

            // even with ensure_ascii, the ill-formed bytes are written as is
            const std::string dumped_ascii = jval.dump(-1, ' ', true, eh::keep);
            CHECK(dumped_ascii.find(c.bytes) != std::string::npos);
        }

        // well-formed characters around an ill-formed sequence are still
        // escaped as usual under ensure_ascii
        const json mixed = valid_sequence() + ill_formed_cases()[1].bytes; // "é" + lone 0xFF
        const std::string dumped_mixed = mixed.dump(-1, ' ', true, eh::keep);
        CHECK(dumped_mixed.find("\\u00e9") != std::string::npos);
        CHECK(dumped_mixed.find(ill_formed_cases()[1].bytes) != std::string::npos);

        // the byte that ends an ill-formed sequence is read again, so a quote,
        // a backslash, or a control character after it is still escaped, and
        // a well-formed code point after it is escaped under ensure_ascii
        for (const bool ensure_ascii :
                {
                    false, true
                })
        {
            CAPTURE(ensure_ascii)
            CHECK(json("\xC3\"").dump(-1, ' ', ensure_ascii, eh::keep) == "\"\xC3\\\"\"");
            CHECK(json("\xC3\\").dump(-1, ' ', ensure_ascii, eh::keep) == "\"\xC3\\\\\"");
            CHECK(json("\xC3\n").dump(-1, ' ', ensure_ascii, eh::keep) == "\"\xC3\\n\"");
            CHECK(json("\xE2\x82\"").dump(-1, ' ', ensure_ascii, eh::keep) == "\"\xE2\x82\\\"\"");
            CHECK(json("\xFF\"").dump(-1, ' ', ensure_ascii, eh::keep) == "\"\xFF\\\"\"");
            CHECK(json("a\xE2\x82").dump(-1, ' ', ensure_ascii, eh::keep) == "\"a\xE2\x82\"");
        }
        CHECK(json("\xC3\xC3\xA9").dump(-1, ' ', false, eh::keep) == "\"\xC3\xC3\xA9\"");
        CHECK(json("\xC3\xC3\xA9").dump(-1, ' ', true, eh::keep) == "\"\xC3\\u00e9\"");
    }

    SECTION("to_msgpack defaults to keep; to_bon8 is not affected by error_handler")
    {
        const json jval = ill_formed_cases()[1].bytes; // lone 0xFF

        // to_msgpack's error_handler defaults to keep, as MessagePack's spec
        // allows any bytes in a str, so the bytes are passed through
        CHECK(json::to_msgpack(jval) == json::to_msgpack(jval, eh::keep));
        CHECK(json::from_msgpack(json::to_msgpack(jval)).get<std::string>() == ill_formed_cases()[1].bytes);

        // the diagnostics context of an ill-formed key is the object
        json jobj;
        jobj["\xFF"] = 1;
        CHECK_THROWS_WITH_AS(json::to_msgpack(jobj, eh::strict), "[json.exception.type_error.316] invalid UTF-8 byte at index 0: 0xFF", json::type_error&);

        // to_bon8 has no error_handler parameter; UTF-8 is structural for
        // BON8, so it always rejects ill-formed input
        CHECK_THROWS_AS(json::to_bon8(jval), json::type_error&);
    }

    SECTION("allow_exceptions=false with error_handler_t::strict discards the value")
    {
        const auto bytes = json::to_cbor(json(ill_formed_cases()[0].bytes), eh::keep);
        const json result = json::from_cbor(bytes, true, false, json::cbor_tag_handler_t::error, eh::strict);
        CHECK(result.is_discarded());
    }

    SECTION("default parameters are unchanged")
    {
        const json jval = ill_formed_cases()[0].bytes;

        // to_*: the default error_handler is keep, so ill-formed bytes are
        // written unchanged, exactly as in release 3.12.0 (it is strict only
        // if JSON_STRICT_BINARY_UTF8 is enabled, see
        // unit-binary_utf8_strict.cpp)
        CHECK(json::to_cbor(jval) == json::to_cbor(jval, eh::keep));
        CHECK(json::to_ubjson(jval) == json::to_ubjson(jval, false, false, eh::keep));
        CHECK(json::to_bjdata(jval) == json::to_bjdata(jval, false, false, json::bjdata_version_t::draft2, eh::keep));
        {
            json jobj;
            jobj["k"] = jval;
            CHECK(json::to_bson(jobj) == json::to_bson(jobj, eh::keep));
        }

        // from_*: the default error_handler is keep, so ill-formed bytes are
        // still accepted unchanged, exactly as in release 3.12.0
        const auto cbor_bytes = json::to_cbor(jval, eh::keep);
        CHECK(json::from_cbor(cbor_bytes).get<std::string>() == ill_formed_cases()[0].bytes);
        const auto ubjson_bytes = json::to_ubjson(jval, false, false, eh::keep);
        CHECK(json::from_ubjson(ubjson_bytes).get<std::string>() == ill_formed_cases()[0].bytes);
        const auto bjdata_bytes = json::to_bjdata(jval, false, false, json::bjdata_version_t::draft2, eh::keep);
        CHECK(json::from_bjdata(bjdata_bytes).get<std::string>() == ill_formed_cases()[0].bytes);
        const auto msgpack_bytes = json::to_msgpack(jval);
        CHECK(json::from_msgpack(msgpack_bytes).get<std::string>() == ill_formed_cases()[0].bytes);
        json bson_obj;
        bson_obj["k"] = jval;
        const auto bson_bytes = json::to_bson(bson_obj, eh::keep);
        CHECK(json::from_bson(bson_bytes)["k"].get<std::string>() == ill_formed_cases()[0].bytes);
    }
}
