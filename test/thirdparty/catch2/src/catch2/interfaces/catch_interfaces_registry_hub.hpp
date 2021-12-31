
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#ifndef CATCH_INTERFACES_REGISTRY_HUB_HPP_INCLUDED
#define CATCH_INTERFACES_REGISTRY_HUB_HPP_INCLUDED

#include <catch2/internal/catch_unique_ptr.hpp>

#include <string>

namespace Catch {

    class TestCaseHandle;
    struct TestCaseInfo;
    struct ITestCaseRegistry;
    struct IExceptionTranslatorRegistry;
    struct IExceptionTranslator;
    struct IReporterRegistry;
    struct IReporterFactory;
    struct ITagAliasRegistry;
    struct ITestInvoker;
    struct IMutableEnumValuesRegistry;
    struct SourceLineInfo;

    class StartupExceptionRegistry;

    using IReporterFactoryPtr = Detail::unique_ptr<IReporterFactory>;

    struct IRegistryHub {
        virtual ~IRegistryHub();

        virtual IReporterRegistry const& getReporterRegistry() const = 0;
        virtual ITestCaseRegistry const& getTestCaseRegistry() const = 0;
        virtual ITagAliasRegistry const& getTagAliasRegistry() const = 0;
        virtual IExceptionTranslatorRegistry const& getExceptionTranslatorRegistry() const = 0;


        virtual StartupExceptionRegistry const& getStartupExceptionRegistry() const = 0;
    };

    struct IMutableRegistryHub {
        virtual ~IMutableRegistryHub();
        virtual void registerReporter( std::string const& name, IReporterFactoryPtr factory ) = 0;
        virtual void registerListener( IReporterFactoryPtr factory ) = 0;
        virtual void registerTest(Detail::unique_ptr<TestCaseInfo>&& testInfo, Detail::unique_ptr<ITestInvoker>&& invoker) = 0;
        virtual void registerTranslator( const IExceptionTranslator* translator ) = 0;
        virtual void registerTagAlias( std::string const& alias, std::string const& tag, SourceLineInfo const& lineInfo ) = 0;
        virtual void registerStartupException() noexcept = 0;
        virtual IMutableEnumValuesRegistry& getMutableEnumValuesRegistry() = 0;
    };

    IRegistryHub const& getRegistryHub();
    IMutableRegistryHub& getMutableRegistryHub();
    void cleanUp();
    std::string translateActiveException();

}

#endif // CATCH_INTERFACES_REGISTRY_HUB_HPP_INCLUDED
