// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.

// Simple test for a fuzzer. The fuzzer must find a particular string.
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  // TODO: check other sizes.
  if (Size >= 8 && memcmp(Data, "01234567", 8) == 0) {
    if (Size >= 12 && memcmp(Data + 8, "ABCD", 4) == 0) {
      if (Size >= 14 && memcmp(Data + 12, "XY", 2) == 0) {
        if (Size >= 17 && memcmp(Data + 14, "KLM", 3) == 0) {
          if (Size >= 27 && memcmp(Data + 17, "ABCDE-GHIJ", 10) == 0){
            fprintf(stderr, "BINGO %zd\n", Size);
            for (size_t i = 0; i < Size; i++) {
              uint8_t C = Data[i];
              if (C >= 32 && C < 127)
                fprintf(stderr, "%c", C);
            }
            fprintf(stderr, "\n");
            exit(1);
          }
        }
      }
    }
  }
  return 0;
}
