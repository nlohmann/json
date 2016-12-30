// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.

// Test that we can find the minimal item in the corpus (3 bytes: "FUZ").
#include <cstdint>
#include <cstdlib>
#include <cstddef>
#include <cstring>
#include <cstdio>

static volatile uint32_t Sink;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < sizeof(uint32_t)) return 0;
  uint32_t X, Y;
  size_t Offset = Size < 8 ? 0 : Size / 2;
  memcpy(&X, Data + Offset, sizeof(uint32_t));
  memcpy(&Y, "FUZZ", sizeof(uint32_t));
  Sink = X == Y;
  return 0;
}

