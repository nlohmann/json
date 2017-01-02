// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.

// The fuzzer must find several constants with swapped bytes.
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < 14) return 0;
  uint64_t x = 0;
  uint32_t y = 0;
  uint16_t z = 0;
  memcpy(&x, Data, sizeof(x));
  memcpy(&y, Data + Size / 2, sizeof(y));
  memcpy(&z, Data + Size - sizeof(z), sizeof(z));

  x = __builtin_bswap64(x);
  y = __builtin_bswap32(y);
  z = __builtin_bswap16(z);

  if (x == 0x46555A5A5A5A5546ULL &&
      z == 0x4F4B &&
      y == 0x66757A7A &&
      true
      ) {
    if (Data[Size - 3] == 'z') {
      fprintf(stderr, "BINGO; Found the target\n");
      exit(1);
    }
  }
  return 0;
}
