//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

// undefine the macros of detail/view/macro_scope.hpp (at the end of json_view.hpp)

#undef NLOHMANN_VIEW_HAS_CPP_17
#undef NLOHMANN_VIEW_LIKELY
#undef NLOHMANN_VIEW_UNLIKELY
#undef NLOHMANN_VIEW_ALWAYS_INLINE
#undef NLOHMANN_VIEW_NOINLINE
#undef NLOHMANN_VIEW_NODISCARD
#undef NLOHMANN_VIEW_THROW
#undef NLOHMANN_VIEW_LITTLE_ENDIAN
#undef NLOHMANN_VIEW_REPEAT16
#undef NLOHMANN_VIEW_NEON
#undef NLOHMANN_VIEW_SSE2
#undef NLOHMANN_VIEW_SSSE3
#undef NLOHMANN_VIEW_SSSE3_DISPATCH
#undef NLOHMANN_VIEW_SSSE3_TARGET
#undef NLOHMANN_VIEW_VECTOR
#undef NLOHMANN_VIEW_VECTOR_UTF8
