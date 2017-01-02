// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.


#include <cstring>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  int Matches = 0;
  for (size_t i = 0; i + 2 < Size; i += 3) {
    const char *Pat = i % 2 ? "foo" : "bar";
    if (!memcmp(Data + i, Pat, 3))
      Matches++;
  }
  if (Matches > 20) {
    fprintf(stderr, "BINGO!\n");
    exit(1);
  }
  return 0;
}
