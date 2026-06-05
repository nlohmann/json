// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.

// Break through a series of strcmp.
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cassert>

bool Eq(const uint8_t *Data, size_t Size, const char *Str) {
  char Buff[1024];
  size_t Len = strlen(Str);
  if (Size < Len) return false;
  if (Len >= sizeof(Buff)) return false;
  memcpy(Buff, (char*)Data, Len);
  Buff[Len] = 0;
  int res = strcmp(Buff, Str);
  return res == 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Eq(Data, Size, "ABC") &&
      Size >= 3 && Eq(Data + 3, Size - 3, "QWER") &&
      Size >= 7 && Eq(Data + 7, Size - 7, "ZXCVN") &&
      Size >= 14 && Data[13] == 42
    ) {
    fprintf(stderr, "BINGO\n");
    exit(1);
  }
  return 0;
}
