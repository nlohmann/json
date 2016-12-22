// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.

// Test with a leak.
#include <cstdint>
#include <cstddef>

static volatile int *Sink;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (!Size) return 0;
  Sink = new int;
  Sink = new int;
  while (Sink) *Sink = 0;  // Infinite loop.
  return 0;
}

