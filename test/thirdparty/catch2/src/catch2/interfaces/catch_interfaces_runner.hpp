
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#ifndef CATCH_INTERFACES_RUNNER_HPP_INCLUDED
#define CATCH_INTERFACES_RUNNER_HPP_INCLUDED

namespace Catch {

    struct IRunner {
        virtual ~IRunner();
        virtual bool aborting() const = 0;
    };
}

#endif // CATCH_INTERFACES_RUNNER_HPP_INCLUDED
