// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.

// Test that libFuzzer itself does not read out of bounds.
#include <assert.h>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cstddef>
#include <iostream>

static volatile int Sink;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < 5) return 0;
  const char *Ch = reinterpret_cast<const char *>(Data);
  if (Ch[Size - 3] == 'a')
    Sink = strncmp(Ch + Size - 3, "abcdefg", 6);
  return 0;
}

