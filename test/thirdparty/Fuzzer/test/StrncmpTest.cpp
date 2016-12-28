// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.

// Simple test for a fuzzer. The fuzzer must find a particular string.
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

static volatile int sink;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  // TODO: check other sizes.
  char *S = (char*)Data;
  if (Size >= 8 && strncmp(S, "123", 8))
    sink = 1;
  if (Size >= 8 && strncmp(S, "01234567", 8) == 0) {
    if (Size >= 12 && strncmp(S + 8, "ABCD", 4) == 0) {
      if (Size >= 14 && strncmp(S + 12, "XY", 2) == 0) {
        if (Size >= 17 && strncmp(S + 14, "KLM", 3) == 0) {
          fprintf(stderr, "BINGO\n");
          exit(1);
        }
      }
    }
  }
  return 0;
}
