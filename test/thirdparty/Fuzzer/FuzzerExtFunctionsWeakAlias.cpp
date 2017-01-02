//===- FuzzerExtFunctionsWeakAlias.cpp - Interface to external functions --===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// Implementation using weak aliases. Works for Windows.
//===----------------------------------------------------------------------===//
#include "FuzzerDefs.h"
#if LIBFUZZER_WINDOWS

#include "FuzzerExtFunctions.h"
#include "FuzzerIO.h"

using namespace fuzzer;

extern "C" {
// Declare these symbols as weak to allow them to be optionally defined.
#define EXT_FUNC(NAME, RETURN_TYPE, FUNC_SIG, WARN)                            \
  RETURN_TYPE NAME##Def FUNC_SIG {                                             \
    Printf("ERROR: Function \"%s\" not defined.\n", #NAME);                    \
    exit(1);                                                                   \
  }                                                                            \
  RETURN_TYPE NAME FUNC_SIG __attribute__((weak, alias(#NAME "Def")));

#include "FuzzerExtFunctions.def"

#undef EXT_FUNC
}

template <typename T>
static T *GetFnPtr(T *Fun, T *FunDef, const char *FnName, bool WarnIfMissing) {
  if (Fun == FunDef) {
    if (WarnIfMissing)
      Printf("WARNING: Failed to find function \"%s\".\n", FnName);
    return nullptr;
  }
  return Fun;
}

namespace fuzzer {

ExternalFunctions::ExternalFunctions() {
#define EXT_FUNC(NAME, RETURN_TYPE, FUNC_SIG, WARN)                            \
  this->NAME = GetFnPtr<decltype(::NAME)>(::NAME, ::NAME##Def, #NAME, WARN);

#include "FuzzerExtFunctions.def"

#undef EXT_FUNC
}

} // namespace fuzzer

#endif // LIBFUZZER_WINDOWS
