// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.

// Tests -trace_malloc
#include <assert.h>
#include <cstdint>
#include <cstdlib>
#include <cstddef>
#include <iostream>

int *Ptr;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (!Size) return 0;
  if (*Data == 1) {
    delete Ptr;
    Ptr = nullptr;
  } else if (*Data == 2) {
    delete Ptr;
    Ptr = new int;
  } else if (*Data == 3) {
    if (!Ptr)
      Ptr = new int;
  }
  return 0;
}

