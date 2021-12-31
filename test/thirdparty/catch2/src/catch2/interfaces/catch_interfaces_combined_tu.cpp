
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
/** \file
 * This is a special TU that combines what would otherwise be a very
 * small interfaces-related TUs into one bigger TU.
 *
 * The reason for this is compilation performance improvements by
 * avoiding reparsing headers for many small TUs, instead having this
 * one TU include bit more, but having it all parsed only once.
 *
 * To avoid heavy-tail problem with compilation times, each "subpart"
 * of Catch2 has its own combined TU like this.
 */

///////////////////////////////////////////////////
// vvv formerly catch_interfaces_capture.cpp vvv //
///////////////////////////////////////////////////

#include <catch2/interfaces/catch_interfaces_capture.hpp>

namespace Catch {
    IResultCapture::~IResultCapture() = default;
}


//////////////////////////////////////////////////
// vvv formerly catch_interfaces_config.cpp vvv //
//////////////////////////////////////////////////

#include <catch2/interfaces/catch_interfaces_config.hpp>

namespace Catch {
    IConfig::~IConfig() = default;
}


/////////////////////////////////////////////////////
// vvv formerly catch_interfaces_exception.cpp vvv //
/////////////////////////////////////////////////////

#include <catch2/interfaces/catch_interfaces_exception.hpp>

namespace Catch {
    IExceptionTranslator::~IExceptionTranslator() = default;
    IExceptionTranslatorRegistry::~IExceptionTranslatorRegistry() = default;
}


////////////////////////////////////////////////////////
// vvv formerly catch_interfaces_registry_hub.cpp vvv //
////////////////////////////////////////////////////////

#include <catch2/interfaces/catch_interfaces_registry_hub.hpp>

namespace Catch {
    IRegistryHub::~IRegistryHub() = default;
    IMutableRegistryHub::~IMutableRegistryHub() = default;
}


//////////////////////////////////////////////////
// vvv formerly catch_interfaces_runner.cpp vvv //
//////////////////////////////////////////////////

#include <catch2/interfaces/catch_interfaces_runner.hpp>

namespace Catch {
    IRunner::~IRunner() = default;
}


////////////////////////////////////////////////////
// vvv formerly catch_interfaces_testcase.cpp vvv //
////////////////////////////////////////////////////

#include <catch2/interfaces/catch_interfaces_testcase.hpp>

namespace Catch {
    ITestInvoker::~ITestInvoker() = default;
    ITestCaseRegistry::~ITestCaseRegistry() = default;
}


#include <catch2/interfaces/catch_interfaces_reporter_registry.hpp>
namespace Catch {
    IReporterRegistry::~IReporterRegistry() = default;
}


#include <catch2/interfaces/catch_interfaces_reporter_factory.hpp>

namespace Catch {
    IReporterFactory::~IReporterFactory() = default;
}
