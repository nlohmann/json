//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include <version>

import std;
import nlohmann.json;

using nlohmann::json;

#if defined(__cpp_impl_reflection)

namespace
{

enum class Color
{
    RED,
    GREEN,
    BLUE,
};

struct Pixel
{
    [[ = nlohmann::rename("x_pos")]] int x = 0;
    [[ = nlohmann::rename("y_pos")]] int y = 0;
    Color color = Color::RED;
    [[ = nlohmann::transient]] int cached = 0;
};

}  // namespace

#endif

int main()
{
#if defined(__cpp_impl_reflection)
    const Pixel p =
    {
        .x = 3,
        .y = 4,
        .color = Color::BLUE,
        .cached = 99,
    };

    // serialize: rename, enum-by-name, and a skipped (transient) member
    const json j = json::serialize(p);
    const bool serialized_ok = j.contains("x_pos") // renamed key
                               && !j.contains("x") // original name not used
                               && !j.contains("cached") // transient omitted
                               && j.at("x_pos") == 3
                               && j.at("y_pos") == 4
                               && j.at("color") == "BLUE"; // enum as its name

    // deserialize: round-trip back into a struct
    const Pixel back = j.deserialize<Pixel>();
    const bool deserialized_ok = back.x == 3
                                 && back.y == 4
                                 && back.color == Color::BLUE
                                 && back.cached == 0; // transient stays default

    // deserialize from freshly parsed text; a missing key keeps the default
    const Pixel from_text = json::parse(R"({"x_pos": 7})").deserialize<Pixel>();
    const bool from_text_ok = from_text.x == 7
                              && from_text.y == 0
                              && from_text.color == Color::RED;

    return (serialized_ok && deserialized_ok && from_text_ok) ? 0 : 1;
#else
    return 0;
#endif
}
