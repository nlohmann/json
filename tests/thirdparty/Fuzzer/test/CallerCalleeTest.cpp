// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.

// Simple test for a fuzzer.
// Try to find the target using the indirect caller-callee pairs.
#include <cstdint>
#include <cstdlib>
#include <cstddef>
#include <cstring>
#include <iostream>

typedef void (*F)();
static F t[256];

void f34() {
  std::cerr << "BINGO\n";
  exit(1);
}
void f23() { t[(unsigned)'d'] = f34;}
void f12() { t[(unsigned)'c'] = f23;}
void f01() { t[(unsigned)'b'] = f12;}
void f00() {}

static F t0[256] = {
  f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00,
  f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00,
  f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00,
  f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00,
  f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00,
  f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00,
  f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00,
  f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00,
  f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00,
  f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00,
  f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00,
  f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00,
  f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00,
  f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00,
  f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00,
  f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00, f00,
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < 4) return 0;
  // Spoof the counters.
  for (int i = 0; i < 200; i++) {
    f23();
    f12();
    f01();
  }
  memcpy(t, t0, sizeof(t));
  t[(unsigned)'a'] = f01;
  t[Data[0]]();
  t[Data[1]]();
  t[Data[2]]();
  t[Data[3]]();
  return 0;
}

