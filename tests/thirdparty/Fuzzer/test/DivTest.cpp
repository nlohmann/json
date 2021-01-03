// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.

// Simple test for a fuzzer: find the interesting argument for div.
#include <assert.h>
#include <cstdint>
#include <cstring>
#include <cstddef>
#include <iostream>

static volatile int Sink;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < 4) return 0;
  int a;
  memcpy(&a, Data, 4);
  Sink = 12345678 / (987654 - a);
  return 0;
}

