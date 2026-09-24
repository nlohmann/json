// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.

// Simple test for a fuzzer. The fuzzer must find several narrow ranges.
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>

extern int AllLines[];

bool PrintOnce(int Line) {
  if (!AllLines[Line])
    fprintf(stderr, "Seen line %d\n", Line);
  AllLines[Line] = 1;
  return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size != 22) return 0;
  uint64_t x = 0;
  int64_t  y = 0;
  int32_t z = 0;
  uint16_t a = 0;
  memcpy(&x, Data, 8);  // 8
  memcpy(&y, Data + 8, 8);  // 16
  memcpy(&z, Data + 16, sizeof(z));  // 20
  memcpy(&a, Data + 20, sizeof(a));  // 22

  if (x > 1234567890 && PrintOnce(__LINE__) &&
      x < 1234567895 && PrintOnce(__LINE__) &&
      a == 0x4242 && PrintOnce(__LINE__) &&
      y >= 987654321 && PrintOnce(__LINE__) &&
      y <= 987654325 && PrintOnce(__LINE__) &&
      z < -10000 && PrintOnce(__LINE__) &&
      z >= -10005 && PrintOnce(__LINE__) &&
      z != -10003 && PrintOnce(__LINE__) &&
      true) {
    fprintf(stderr, "BINGO; Found the target: size %zd (%zd, %zd, %d, %d), exiting.\n",
            Size, x, y, z, a);
    exit(1);
  }
  return 0;
}

int AllLines[__LINE__ + 1];  // Must be the last line.
