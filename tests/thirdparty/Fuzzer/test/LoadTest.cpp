// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.

// Simple test for a fuzzer: find interesting value of array index.
#include <assert.h>
#include <cstdint>
#include <cstring>
#include <cstddef>
#include <iostream>

static volatile int Sink;
const int kArraySize = 1234567;
int array[kArraySize];

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < 8) return 0;
  size_t a = 0;
  memcpy(&a, Data, 8);
  Sink = array[a % (kArraySize + 1)];
  return 0;
}

