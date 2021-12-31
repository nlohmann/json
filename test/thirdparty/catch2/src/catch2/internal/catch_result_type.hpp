
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#ifndef CATCH_RESULT_TYPE_HPP_INCLUDED
#define CATCH_RESULT_TYPE_HPP_INCLUDED

namespace Catch {

    // ResultWas::OfType enum
    struct ResultWas { enum OfType {
        Unknown = -1,
        Ok = 0,
        Info = 1,
        Warning = 2,

        FailureBit = 0x10,

        ExpressionFailed = FailureBit | 1,
        ExplicitFailure = FailureBit | 2,

        Exception = 0x100 | FailureBit,

        ThrewException = Exception | 1,
        DidntThrowException = Exception | 2,

        FatalErrorCondition = 0x200 | FailureBit

    }; };

    bool isOk( ResultWas::OfType resultType );
    bool isJustInfo( int flags );


    // ResultDisposition::Flags enum
    struct ResultDisposition { enum Flags {
        Normal = 0x01,

        ContinueOnFailure = 0x02,   // Failures fail test, but execution continues
        FalseTest = 0x04,           // Prefix expression with !
        SuppressFail = 0x08         // Failures are reported but do not fail the test
    }; };

    ResultDisposition::Flags operator | ( ResultDisposition::Flags lhs, ResultDisposition::Flags rhs );

    bool shouldContinueOnFailure( int flags );
    inline bool isFalseTest( int flags ) { return ( flags & ResultDisposition::FalseTest ) != 0; }
    bool shouldSuppressFailure( int flags );

} // end namespace Catch

#endif // CATCH_RESULT_TYPE_HPP_INCLUDED
