//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

// The binary writers check strings and object keys for valid UTF-8 only if
// JSON_STRICT_BINARY_UTF8 is enabled (planned to be the default in 4.0.0).
// Without it, they write the bytes unchanged, as before version 3.13.0; the
// tests for that are next to the other tests of each format.
#ifdef JSON_STRICT_BINARY_UTF8
    #undef JSON_STRICT_BINARY_UTF8
#endif

#define JSON_STRICT_BINARY_UTF8 1

#include <nlohmann/json.hpp>
using nlohmann::json;

#include <cstdint>
#include <vector>

TEST_CASE("JSON_STRICT_BINARY_UTF8 (see #5529, #5651)")
{
    SECTION("CBOR")
    {
        // a string value with ill-formed UTF-8 is rejected
        CHECK_THROWS_WITH_AS(json::to_cbor(json("\xFF")), "[json.exception.type_error.316] invalid UTF-8 byte at index 0: 0xFF", json::type_error&);
        // a truncated multi-byte sequence
        CHECK_THROWS_WITH_AS(json::to_cbor(json("\xC3")), "[json.exception.type_error.316] invalid UTF-8 byte at index 0: 0xC3", json::type_error&);
        // an encoded surrogate half (U+D800)
        CHECK_THROWS_WITH_AS(json::to_cbor(json("\xED\xA0\x80")), "[json.exception.type_error.316] invalid UTF-8 byte at index 0: 0xED", json::type_error&);
        // an overlong encoding of '.'
        CHECK_THROWS_WITH_AS(json::to_cbor(json("\xC0\xAF")), "[json.exception.type_error.316] invalid UTF-8 byte at index 0: 0xC0", json::type_error&);

        // an object key with ill-formed UTF-8 is rejected the same way
        CHECK_THROWS_WITH_AS(json::to_cbor(json{{"\xFF", 1}}), "[json.exception.type_error.316] invalid UTF-8 byte at index 0: 0xFF", json::type_error&);

        // binary values are not text and are unaffected
        CHECK_NOTHROW(json::to_cbor(json::binary(std::vector<std::uint8_t>({0xFF}))));

        // a value read back from CBOR with ill-formed bytes cannot be written
        // back either (the reader is lenient regardless of the macro)
        const json j = json::from_cbor(std::vector<std::uint8_t>({0x62, 0xc0, 0xae}));
        CHECK_THROWS_WITH_AS(json::to_cbor(j), "[json.exception.type_error.316] invalid UTF-8 byte at index 0: 0xC0", json::type_error&);
    }

    SECTION("UBJSON")
    {
        CHECK_THROWS_WITH_AS(json::to_ubjson(json("\xFF")), "[json.exception.type_error.316] invalid UTF-8 byte at index 0: 0xFF", json::type_error&);
        // a truncated multi-byte sequence
        CHECK_THROWS_WITH_AS(json::to_ubjson(json("\xC3")), "[json.exception.type_error.316] invalid UTF-8 byte at index 0: 0xC3", json::type_error&);
        // an encoded surrogate half (U+D800)
        CHECK_THROWS_WITH_AS(json::to_ubjson(json("\xED\xA0\x80")), "[json.exception.type_error.316] invalid UTF-8 byte at index 0: 0xED", json::type_error&);
        // an overlong encoding of '.'
        CHECK_THROWS_WITH_AS(json::to_ubjson(json("\xC0\xAF")), "[json.exception.type_error.316] invalid UTF-8 byte at index 0: 0xC0", json::type_error&);

        // an object key with ill-formed UTF-8 is rejected the same way
        CHECK_THROWS_WITH_AS(json::to_ubjson(json{{"\xFF", 1}}), "[json.exception.type_error.316] invalid UTF-8 byte at index 0: 0xFF", json::type_error&);
    }

    SECTION("BJData")
    {
        CHECK_THROWS_WITH_AS(json::to_bjdata(json("\xFF")), "[json.exception.type_error.316] invalid UTF-8 byte at index 0: 0xFF", json::type_error&);
        // a truncated multi-byte sequence
        CHECK_THROWS_WITH_AS(json::to_bjdata(json("\xC3")), "[json.exception.type_error.316] invalid UTF-8 byte at index 0: 0xC3", json::type_error&);
        // an encoded surrogate half (U+D800)
        CHECK_THROWS_WITH_AS(json::to_bjdata(json("\xED\xA0\x80")), "[json.exception.type_error.316] invalid UTF-8 byte at index 0: 0xED", json::type_error&);
        // an overlong encoding of '.'
        CHECK_THROWS_WITH_AS(json::to_bjdata(json("\xC0\xAF")), "[json.exception.type_error.316] invalid UTF-8 byte at index 0: 0xC0", json::type_error&);

        // an object key with ill-formed UTF-8 is rejected the same way
        CHECK_THROWS_WITH_AS(json::to_bjdata(json{{"\xFF", 1}}), "[json.exception.type_error.316] invalid UTF-8 byte at index 0: 0xFF", json::type_error&);
    }

    SECTION("BSON")
    {
        // to_bson() rejects the same kind of ill-formed string value, before
        // any bytes reach the output adapter (the BSON document length
        // prefix must be known up front, so nothing is written incrementally)
        std::vector<std::uint8_t> out{0x42}; // a sentinel byte the writer must not touch
#if JSON_DIAGNOSTICS
        CHECK_THROWS_WITH_AS(json::to_bson(json {{"s", "\xFF"}}, nlohmann::detail::output_adapter<std::uint8_t>(out)), "[json.exception.type_error.316] (/s) invalid UTF-8 byte at index 0: 0xFF", json::type_error&);
#else
        CHECK_THROWS_WITH_AS(json::to_bson(json {{"s", "\xFF"}}, nlohmann::detail::output_adapter<std::uint8_t>(out)), "[json.exception.type_error.316] invalid UTF-8 byte at index 0: 0xFF", json::type_error&);
#endif
        CHECK(out == std::vector<std::uint8_t> {0x42});

#if JSON_DIAGNOSTICS
        CHECK_THROWS_WITH_AS(json::to_bson(json {{"s", "\xFF"}}), "[json.exception.type_error.316] (/s) invalid UTF-8 byte at index 0: 0xFF", json::type_error&);
#else
        CHECK_THROWS_WITH_AS(json::to_bson(json {{"s", "\xFF"}}), "[json.exception.type_error.316] invalid UTF-8 byte at index 0: 0xFF", json::type_error&);
#endif
        // a truncated multi-byte sequence
#if JSON_DIAGNOSTICS
        CHECK_THROWS_WITH_AS(json::to_bson(json {{"s", "\xC3"}}), "[json.exception.type_error.316] (/s) invalid UTF-8 byte at index 0: 0xC3", json::type_error&);
#else
        CHECK_THROWS_WITH_AS(json::to_bson(json {{"s", "\xC3"}}), "[json.exception.type_error.316] invalid UTF-8 byte at index 0: 0xC3", json::type_error&);
#endif
        // an encoded surrogate half (U+D800)
#if JSON_DIAGNOSTICS
        CHECK_THROWS_WITH_AS(json::to_bson(json {{"s", "\xED\xA0\x80"}}), "[json.exception.type_error.316] (/s) invalid UTF-8 byte at index 0: 0xED", json::type_error&);
#else
        CHECK_THROWS_WITH_AS(json::to_bson(json {{"s", "\xED\xA0\x80"}}), "[json.exception.type_error.316] invalid UTF-8 byte at index 0: 0xED", json::type_error&);
#endif
        // an overlong encoding of '.'
#if JSON_DIAGNOSTICS
        CHECK_THROWS_WITH_AS(json::to_bson(json {{"s", "\xC0\xAF"}}), "[json.exception.type_error.316] (/s) invalid UTF-8 byte at index 0: 0xC0", json::type_error&);
#else
        CHECK_THROWS_WITH_AS(json::to_bson(json {{"s", "\xC0\xAF"}}), "[json.exception.type_error.316] invalid UTF-8 byte at index 0: 0xC0", json::type_error&);
#endif

        // an object key with ill-formed UTF-8 is rejected as well; unlike
        // the reader (which never validates element names), the writer
        // checks both string values and object keys
#if JSON_DIAGNOSTICS
        CHECK_THROWS_WITH_AS(json::to_bson(json {{"\xFF", 1}}), "[json.exception.type_error.316] (/\xFF) invalid UTF-8 byte at index 0: 0xFF", json::type_error&);
#else
        CHECK_THROWS_WITH_AS(json::to_bson(json {{"\xFF", 1}}), "[json.exception.type_error.316] invalid UTF-8 byte at index 0: 0xFF", json::type_error&);
#endif
    }

    SECTION("an explicit error_handler overrides the default")
    {
        // the macro only changes the default of the error_handler parameter
        CHECK(json::to_cbor(json("\xFF"), json::error_handler_t::keep) == std::vector<std::uint8_t>({0x61, 0xff}));
        CHECK(json::to_ubjson(json("\xFF"), false, false, json::error_handler_t::keep) == std::vector<std::uint8_t>({'S', 'i', 1, 0xff}));
        CHECK(json::to_bjdata(json("\xFF"), false, false, json::bjdata_version_t::draft2, json::error_handler_t::keep) == std::vector<std::uint8_t>({'S', 'i', 1, 0xff}));
        CHECK(json::from_bson(json::to_bson(json{{"s", "\xFF"}}, json::error_handler_t::keep)) == json{{"s", "\xFF"}});
        CHECK(json::to_cbor(json("\xFF"), json::error_handler_t::replace) == std::vector<std::uint8_t>({0x63, 0xef, 0xbf, 0xbd}));
    }

    SECTION("MessagePack and BON8 are unaffected")
    {
        // MessagePack allows any bytes in a str, so to_msgpack() still
        // defaults to keep (strict only if passed explicitly); BON8 always
        // checks, because the lead bytes mark where strings end
        CHECK(json::to_msgpack(json("\xFF")) == std::vector<std::uint8_t>({0xa1, 0xff}));
        CHECK_THROWS_AS(json::to_msgpack(json("\xFF"), json::error_handler_t::strict), json::type_error&);
        CHECK_THROWS_AS(json::to_bon8(json("\xFF")), json::type_error&);
    }
}
