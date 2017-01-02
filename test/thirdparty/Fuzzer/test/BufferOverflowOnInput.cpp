// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.

// Simple test for a fuzzer. The fuzzer must find the string "Hi!".
#include <assert.h>
#include <cstdint>
#include <cstdlib>
#include <cstddef>
#include <iostream>

static volatile bool SeedLargeBuffer;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  assert(Data);
  if (Size >= 4)
    SeedLargeBuffer = true;
  if (Size == 3 && SeedLargeBuffer && Data[3]) {
    std::cout << "Woops, reading Data[3] w/o crashing\n";
    exit(1);
  }
  return 0;
}

