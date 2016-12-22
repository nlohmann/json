// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.

// Simple test for a fuzzer. The fuzzer must find the interesting switch value.
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <cstddef>

static volatile int Sink;

template<class T>
bool Switch(const uint8_t *Data, size_t Size) {
  T X;
  if (Size < sizeof(X)) return false;
  memcpy(&X, Data, sizeof(X));
  switch (X) {
    case 1: Sink = __LINE__; break;
    case 101: Sink = __LINE__; break;
    case 1001: Sink = __LINE__; break;
    case 10001: Sink = __LINE__; break;
//    case 100001: Sink = __LINE__; break;
//    case 1000001: Sink = __LINE__; break;
    case 10000001: Sink = __LINE__; break;
    case 100000001: return true;
  }
  return false;
}

bool ShortSwitch(const uint8_t *Data, size_t Size) {
  short X;
  if (Size < sizeof(short)) return false;
  memcpy(&X, Data, sizeof(short));
  switch(X) {
    case 42: Sink = __LINE__; break;
    case 402: Sink = __LINE__; break;
    case 4002: Sink = __LINE__; break;
    case 5002: Sink = __LINE__; break;
    case 7002: Sink = __LINE__; break;
    case 9002: Sink = __LINE__; break;
    case 14002: Sink = __LINE__; break;
    case 21402: return true;
  }
  return false;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size >= 4  && Switch<int>(Data, Size) &&
      Size >= 12 && Switch<uint64_t>(Data + 4, Size - 4) &&
      Size >= 14 && ShortSwitch(Data + 12, 2)
    ) {
    fprintf(stderr, "BINGO; Found the target, exiting\n");
    exit(1);
  }
  return 0;
}

