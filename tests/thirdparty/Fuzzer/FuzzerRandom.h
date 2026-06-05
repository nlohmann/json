//===- FuzzerRandom.h - Internal header for the Fuzzer ----------*- C++ -* ===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// fuzzer::Random
//===----------------------------------------------------------------------===//

#ifndef LLVM_FUZZER_RANDOM_H
#define LLVM_FUZZER_RANDOM_H

#include <random>

namespace fuzzer {
class Random {
 public:
  Random(unsigned int seed) : R(seed) {}
  size_t Rand() { return R(); }
  size_t RandBool() { return Rand() % 2; }
  size_t operator()(size_t n) { return n ? Rand() % n : 0; }
  intptr_t operator()(intptr_t From, intptr_t To) {
    assert(From < To);
    intptr_t RangeSize = To - From + 1;
    return operator()(RangeSize) + From;
  }
  std::mt19937 &Get_mt19937() { return R; }
 private:
  std::mt19937 R;
};

}  // namespace fuzzer

#endif  // LLVM_FUZZER_RANDOM_H
