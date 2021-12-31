
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#include <catch2/internal/catch_result_type.hpp>

namespace Catch {

    bool isOk( ResultWas::OfType resultType ) {
        return ( resultType & ResultWas::FailureBit ) == 0;
    }
    bool isJustInfo( int flags ) {
        return flags == ResultWas::Info;
    }

    ResultDisposition::Flags operator | ( ResultDisposition::Flags lhs, ResultDisposition::Flags rhs ) {
        return static_cast<ResultDisposition::Flags>( static_cast<int>( lhs ) | static_cast<int>( rhs ) );
    }

    bool shouldContinueOnFailure( int flags )    { return ( flags & ResultDisposition::ContinueOnFailure ) != 0; }
    bool shouldSuppressFailure( int flags )      { return ( flags & ResultDisposition::SuppressFail ) != 0; }

} // end namespace Catch
