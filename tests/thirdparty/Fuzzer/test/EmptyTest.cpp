// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
// A fuzzer with empty target function.

#include <cstdint>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  return 0;
}
