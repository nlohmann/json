
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#include <catch2/internal/catch_test_registry.hpp>
#include <catch2/internal/catch_compiler_capabilities.hpp>
#include <catch2/catch_test_case_info.hpp>
#include <catch2/internal/catch_test_case_registry_impl.hpp>
#include <catch2/interfaces/catch_interfaces_registry_hub.hpp>

namespace Catch {

    Detail::unique_ptr<ITestInvoker> makeTestInvoker( void(*testAsFunction)() ) {
        return Detail::unique_ptr<ITestInvoker>( new TestInvokerAsFunction( testAsFunction ));
    }

    AutoReg::AutoReg( Detail::unique_ptr<ITestInvoker> invoker, SourceLineInfo const& lineInfo, StringRef const& classOrMethod, NameAndTags const& nameAndTags ) noexcept {
        CATCH_TRY {
            getMutableRegistryHub()
                    .registerTest(
                        makeTestCaseInfo(
                            extractClassName( classOrMethod ),
                            nameAndTags,
                            lineInfo),
                        std::move(invoker)
                    );
        } CATCH_CATCH_ALL {
            // Do not throw when constructing global objects, instead register the exception to be processed later
            getMutableRegistryHub().registerStartupException();
        }
    }
}
