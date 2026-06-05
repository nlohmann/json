// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.

// Simple test for a fuzzer. The fuzzer must find the interesting switch value.
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <cstddef>

int Switch(int a) {
  switch(a) {
    case 100001: return 1;
    case 100002: return 2;
    case 100003: return 4;
  }
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  const int N = 3;
  if (Size < N * sizeof(int)) return 0;
  int Res = 0;
  for (int i = 0; i < N; i++) {
    int X;
    memcpy(&X, Data + i * sizeof(int), sizeof(int));
    Res += Switch(X);
  }
  if (Res == 5 || Res == 3 || Res == 6 || Res == 7) {
    fprintf(stderr, "BINGO; Found the target, exiting; Res=%d\n", Res);
    exit(1);
  }
  return 0;
}

