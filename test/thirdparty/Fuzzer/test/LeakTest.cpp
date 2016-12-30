// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.

// Test with a leak.
#include <cstdint>
#include <cstddef>

static volatile void *Sink;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size > 0 && *Data == 'H') {
    Sink = new int;
    Sink = nullptr;
  }
  return 0;
}

