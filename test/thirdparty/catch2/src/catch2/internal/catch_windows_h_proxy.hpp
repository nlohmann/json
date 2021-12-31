
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#ifndef CATCH_WINDOWS_H_PROXY_HPP_INCLUDED
#define CATCH_WINDOWS_H_PROXY_HPP_INCLUDED

#include <catch2/internal/catch_platform.hpp>

#if defined(CATCH_PLATFORM_WINDOWS)

#if !defined(NOMINMAX) && !defined(CATCH_CONFIG_NO_NOMINMAX)
#  define CATCH_DEFINED_NOMINMAX
#  define NOMINMAX
#endif
#if !defined(WIN32_LEAN_AND_MEAN) && !defined(CATCH_CONFIG_NO_WIN32_LEAN_AND_MEAN)
#  define CATCH_DEFINED_WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif

#ifdef __AFXDLL
#include <AfxWin.h>
#else
#include <windows.h>
#endif

#ifdef CATCH_DEFINED_NOMINMAX
#  undef NOMINMAX
#endif
#ifdef CATCH_DEFINED_WIN32_LEAN_AND_MEAN
#  undef WIN32_LEAN_AND_MEAN
#endif

#endif // defined(CATCH_PLATFORM_WINDOWS)

#endif // CATCH_WINDOWS_H_PROXY_HPP_INCLUDED
