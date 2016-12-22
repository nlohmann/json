// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.

// abs(x) < 0 and y == Const puzzle.
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <cstddef>
#include <cstdio>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < 8) return 0;
  int x;
  unsigned y;
  memcpy(&x, Data, sizeof(x));
  memcpy(&y, Data + sizeof(x), sizeof(y));
  if (abs(x) < 0 && y == 0xbaddcafe) {
    printf("BINGO; Found the target, exiting; x = 0x%x y 0x%x\n", x, y);
    exit(1);
  }
  return 0;
}

