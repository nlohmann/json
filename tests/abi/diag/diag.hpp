//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef>

std::size_t json_sizeof_diag_on();
std::size_t json_sizeof_diag_on_explicit();

std::size_t json_sizeof_diag_off();
std::size_t json_sizeof_diag_off_explicit();

void json_at_diag_on();
void json_at_diag_off();
