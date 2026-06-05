// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.

// abs(x) < 0 and y == Const puzzle, 64-bit variant.
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <cstddef>
#include <cstdio>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < 16) return 0;
  int64_t x;
  uint64_t y;
  memcpy(&x, Data, sizeof(x));
  memcpy(&y, Data + sizeof(x), sizeof(y));
  if (labs(x) < 0 && y == 0xbaddcafedeadbeefUL) {
    printf("BINGO; Found the target, exiting; x = 0x%lx y 0x%lx\n", x, y);
    exit(1);
  }
  return 0;
}

