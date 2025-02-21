// SPDX-FileCopyrightText: 2025-2026 Mike Crowe
// SPDX-License-Identifier: MIT

#include "clang-tidy/ClangTidyModule.h"
#include "llvm/Config/llvm-config.h"
#if LLVM_VERSION_MAJOR < 22
// LLVM 22 moved ClangTidyModuleRegistry into ClangTidyModule.h and deprecated this header
#include "clang-tidy/ClangTidyModuleRegistry.h"
#endif
#include "ModernizeNlohmannJsonExplicitConversionsCheck.h"

namespace {

    using namespace clang::tidy;

class NlohmannJsonChecksModule : public ClangTidyModule
{
public:
    void addCheckFactories(ClangTidyCheckFactories& CheckFactories) override
    {
        CheckFactories.registerCheck<clang::tidy::modernize::NlohmannJsonExplicitConversionsCheck>(
            "modernize-nlohmann-json-explicit-conversions");
    }
};

}  // namespace

namespace clang::tidy {

// Register the module using this statically initialized variable.
    static ClangTidyModuleRegistry::Add<::NlohmannJsonChecksModule> nlohmannJsonChecksInit(
    "nlohmann-json-checks-module",
    "Adds 'modernize-nlohmann-json-explicit-conversions' check.");

}  // namespace clang::tidy
