//===- FuzzerTraceState.cpp - Trace-based fuzzer mutator ------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// Data tracing.
//===----------------------------------------------------------------------===//

#include "FuzzerDictionary.h"
#include "FuzzerInternal.h"
#include "FuzzerIO.h"
#include "FuzzerMutate.h"
#include "FuzzerRandom.h"
#include "FuzzerTracePC.h"
#include <algorithm>
#include <cstring>
#include <map>
#include <set>
#include <thread>

namespace fuzzer {

// For now, very simple: put Size bytes of Data at position Pos.
struct TraceBasedMutation {
  uint32_t Pos;
  Word W;
};

// Declared as static globals for faster checks inside the hooks.
static bool RecordingMemcmp = false;
static bool RecordingMemmem = false;
static bool DoingMyOwnMemmem = false;

ScopedDoingMyOwnMemmem::ScopedDoingMyOwnMemmem() { DoingMyOwnMemmem = true; }
ScopedDoingMyOwnMemmem::~ScopedDoingMyOwnMemmem() { DoingMyOwnMemmem = false; }

class TraceState {
public:
  TraceState(MutationDispatcher &MD, const FuzzingOptions &Options,
             const Fuzzer *F)
      : MD(MD), Options(Options), F(F) {}

  void TraceMemcmpCallback(size_t CmpSize, const uint8_t *Data1,
                           const uint8_t *Data2);

  void TraceSwitchCallback(uintptr_t PC, size_t ValSizeInBits, uint64_t Val,
                           size_t NumCases, uint64_t *Cases);
  int TryToAddDesiredData(uint64_t PresentData, uint64_t DesiredData,
                          size_t DataSize);
  int TryToAddDesiredData(const uint8_t *PresentData,
                          const uint8_t *DesiredData, size_t DataSize);

  void StartTraceRecording() {
    if (!Options.UseMemcmp)
      return;
    RecordingMemcmp = Options.UseMemcmp;
    RecordingMemmem = Options.UseMemmem;
    NumMutations = 0;
    InterestingWords.clear();
    MD.ClearAutoDictionary();
  }

  void StopTraceRecording() {
    if (!RecordingMemcmp)
      return;
    RecordingMemcmp = false;
    for (size_t i = 0; i < NumMutations; i++) {
      auto &M = Mutations[i];
      if (Options.Verbosity >= 2) {
        AutoDictUnitCounts[M.W]++;
        AutoDictAdds++;
        if ((AutoDictAdds & (AutoDictAdds - 1)) == 0) {
          typedef std::pair<size_t, Word> CU;
          std::vector<CU> CountedUnits;
          for (auto &I : AutoDictUnitCounts)
            CountedUnits.push_back(std::make_pair(I.second, I.first));
          std::sort(CountedUnits.begin(), CountedUnits.end(),
                    [](const CU &a, const CU &b) { return a.first > b.first; });
          Printf("AutoDict:\n");
          for (auto &I : CountedUnits) {
            Printf("   %zd ", I.first);
            PrintASCII(I.second.data(), I.second.size());
            Printf("\n");
          }
        }
      }
      MD.AddWordToAutoDictionary({M.W, M.Pos});
    }
    for (auto &W : InterestingWords)
      MD.AddWordToAutoDictionary({W});
  }

  void AddMutation(uint32_t Pos, uint32_t Size, const uint8_t *Data) {
    if (NumMutations >= kMaxMutations) return;
    auto &M = Mutations[NumMutations++];
    M.Pos = Pos;
    M.W.Set(Data, Size);
  }

  void AddMutation(uint32_t Pos, uint32_t Size, uint64_t Data) {
    assert(Size <= sizeof(Data));
    AddMutation(Pos, Size, reinterpret_cast<uint8_t*>(&Data));
  }

  void AddInterestingWord(const uint8_t *Data, size_t Size) {
    if (!RecordingMemmem || !F->InFuzzingThread()) return;
    if (Size <= 1) return;
    Size = std::min(Size, Word::GetMaxSize());
    Word W(Data, Size);
    InterestingWords.insert(W);
  }

 private:
  bool IsTwoByteData(uint64_t Data) {
    int64_t Signed = static_cast<int64_t>(Data);
    Signed >>= 16;
    return Signed == 0 || Signed == -1L;
  }

  // We don't want to create too many trace-based mutations as it is both
  // expensive and useless. So after some number of mutations is collected,
  // start rejecting some of them. The more there are mutations the more we
  // reject.
  bool WantToHandleOneMoreMutation() {
    const size_t FirstN = 64;
    // Gladly handle first N mutations.
    if (NumMutations <= FirstN) return true;
    size_t Diff = NumMutations - FirstN;
    size_t DiffLog = sizeof(long) * 8 - __builtin_clzl((long)Diff);
    assert(DiffLog > 0 && DiffLog < 64);
    bool WantThisOne = MD.GetRand()(1 << DiffLog) == 0;  // 1 out of DiffLog.
    return WantThisOne;
  }

  static const size_t kMaxMutations = 1 << 16;
  size_t NumMutations;
  TraceBasedMutation Mutations[kMaxMutations];
  // TODO: std::set is too inefficient, need to have a custom DS here.
  std::set<Word> InterestingWords;
  MutationDispatcher &MD;
  const FuzzingOptions Options;
  const Fuzzer *F;
  std::map<Word, size_t> AutoDictUnitCounts;
  size_t AutoDictAdds = 0;
};

int TraceState::TryToAddDesiredData(uint64_t PresentData, uint64_t DesiredData,
                                    size_t DataSize) {
  if (NumMutations >= kMaxMutations || !WantToHandleOneMoreMutation()) return 0;
  ScopedDoingMyOwnMemmem scoped_doing_my_own_memmem;
  const uint8_t *UnitData;
  auto UnitSize = F->GetCurrentUnitInFuzzingThead(&UnitData);
  int Res = 0;
  const uint8_t *Beg = UnitData;
  const uint8_t *End = Beg + UnitSize;
  for (const uint8_t *Cur = Beg; Cur < End; Cur++) {
    Cur = (uint8_t *)SearchMemory(Cur, End - Cur, &PresentData, DataSize);
    if (!Cur)
      break;
    size_t Pos = Cur - Beg;
    assert(Pos < UnitSize);
    AddMutation(Pos, DataSize, DesiredData);
    AddMutation(Pos, DataSize, DesiredData + 1);
    AddMutation(Pos, DataSize, DesiredData - 1);
    Res++;
  }
  return Res;
}

int TraceState::TryToAddDesiredData(const uint8_t *PresentData,
                                    const uint8_t *DesiredData,
                                    size_t DataSize) {
  if (NumMutations >= kMaxMutations || !WantToHandleOneMoreMutation()) return 0;
  ScopedDoingMyOwnMemmem scoped_doing_my_own_memmem;
  const uint8_t *UnitData;
  auto UnitSize = F->GetCurrentUnitInFuzzingThead(&UnitData);
  int Res = 0;
  const uint8_t *Beg = UnitData;
  const uint8_t *End = Beg + UnitSize;
  for (const uint8_t *Cur = Beg; Cur < End; Cur++) {
    Cur = (uint8_t *)SearchMemory(Cur, End - Cur, PresentData, DataSize);
    if (!Cur)
      break;
    size_t Pos = Cur - Beg;
    assert(Pos < UnitSize);
    AddMutation(Pos, DataSize, DesiredData);
    Res++;
  }
  return Res;
}

void TraceState::TraceMemcmpCallback(size_t CmpSize, const uint8_t *Data1,
                                     const uint8_t *Data2) {
  if (!RecordingMemcmp || !F->InFuzzingThread()) return;
  CmpSize = std::min(CmpSize, Word::GetMaxSize());
  int Added2 = TryToAddDesiredData(Data1, Data2, CmpSize);
  int Added1 = TryToAddDesiredData(Data2, Data1, CmpSize);
  if ((Added1 || Added2) && Options.Verbosity >= 3) {
    Printf("MemCmp Added %d%d: ", Added1, Added2);
    if (Added1) PrintASCII(Data1, CmpSize);
    if (Added2) PrintASCII(Data2, CmpSize);
    Printf("\n");
  }
}

void TraceState::TraceSwitchCallback(uintptr_t PC, size_t ValSizeInBits,
                                     uint64_t Val, size_t NumCases,
                                     uint64_t *Cases) {
  if (F->InFuzzingThread()) return;
  size_t ValSize = ValSizeInBits / 8;
  bool TryShort = IsTwoByteData(Val);
  for (size_t i = 0; i < NumCases; i++)
    TryShort &= IsTwoByteData(Cases[i]);

  if (Options.Verbosity >= 3)
    Printf("TraceSwitch: %p %zd # %zd; TryShort %d\n", PC, Val, NumCases,
           TryShort);

  for (size_t i = 0; i < NumCases; i++) {
    TryToAddDesiredData(Val, Cases[i], ValSize);
    if (TryShort)
      TryToAddDesiredData(Val, Cases[i], 2);
  }
}

static TraceState *TS;

void Fuzzer::StartTraceRecording() {
  if (!TS) return;
  TS->StartTraceRecording();
}

void Fuzzer::StopTraceRecording() {
  if (!TS) return;
  TS->StopTraceRecording();
}

void Fuzzer::InitializeTraceState() {
  if (!Options.UseMemcmp) return;
  TS = new TraceState(MD, Options, this);
}

static size_t InternalStrnlen(const char *S, size_t MaxLen) {
  size_t Len = 0;
  for (; Len < MaxLen && S[Len]; Len++) {}
  return Len;
}

}  // namespace fuzzer

using fuzzer::TS;
using fuzzer::RecordingMemcmp;

extern "C" {

// We may need to avoid defining weak hooks to stay compatible with older clang.
#ifndef LLVM_FUZZER_DEFINES_SANITIZER_WEAK_HOOOKS
# define LLVM_FUZZER_DEFINES_SANITIZER_WEAK_HOOOKS 1
#endif

#if LLVM_FUZZER_DEFINES_SANITIZER_WEAK_HOOOKS
void __sanitizer_weak_hook_memcmp(void *caller_pc, const void *s1,
                                  const void *s2, size_t n, int result) {
  fuzzer::TPC.AddValueForMemcmp(caller_pc, s1, s2, n);
  if (!RecordingMemcmp) return;
  if (result == 0) return;  // No reason to mutate.
  if (n <= 1) return;  // Not interesting.
  TS->TraceMemcmpCallback(n, reinterpret_cast<const uint8_t *>(s1),
                          reinterpret_cast<const uint8_t *>(s2));
}

void __sanitizer_weak_hook_strncmp(void *caller_pc, const char *s1,
                                   const char *s2, size_t n, int result) {
  fuzzer::TPC.AddValueForStrcmp(caller_pc, s1, s2, n);
  if (!RecordingMemcmp) return;
  if (result == 0) return;  // No reason to mutate.
  size_t Len1 = fuzzer::InternalStrnlen(s1, n);
  size_t Len2 = fuzzer::InternalStrnlen(s2, n);
  n = std::min(n, Len1);
  n = std::min(n, Len2);
  if (n <= 1) return;  // Not interesting.
  TS->TraceMemcmpCallback(n, reinterpret_cast<const uint8_t *>(s1),
                          reinterpret_cast<const uint8_t *>(s2));
}

void __sanitizer_weak_hook_strcmp(void *caller_pc, const char *s1,
                                   const char *s2, int result) {
  fuzzer::TPC.AddValueForStrcmp(caller_pc, s1, s2, 64);
  if (!RecordingMemcmp) return;
  if (result == 0) return;  // No reason to mutate.
  size_t Len1 = strlen(s1);
  size_t Len2 = strlen(s2);
  size_t N = std::min(Len1, Len2);
  if (N <= 1) return;  // Not interesting.
  TS->TraceMemcmpCallback(N, reinterpret_cast<const uint8_t *>(s1),
                          reinterpret_cast<const uint8_t *>(s2));
}

void __sanitizer_weak_hook_strncasecmp(void *called_pc, const char *s1,
                                       const char *s2, size_t n, int result) {
  return __sanitizer_weak_hook_strncmp(called_pc, s1, s2, n, result);
}
void __sanitizer_weak_hook_strcasecmp(void *called_pc, const char *s1,
                                      const char *s2, int result) {
  return __sanitizer_weak_hook_strcmp(called_pc, s1, s2, result);
}
void __sanitizer_weak_hook_strstr(void *called_pc, const char *s1,
                                  const char *s2, char *result) {
  TS->AddInterestingWord(reinterpret_cast<const uint8_t *>(s2), strlen(s2));
}
void __sanitizer_weak_hook_strcasestr(void *called_pc, const char *s1,
                                      const char *s2, char *result) {
  TS->AddInterestingWord(reinterpret_cast<const uint8_t *>(s2), strlen(s2));
}
void __sanitizer_weak_hook_memmem(void *called_pc, const void *s1, size_t len1,
                                  const void *s2, size_t len2, void *result) {
  if (fuzzer::DoingMyOwnMemmem) return;
  TS->AddInterestingWord(reinterpret_cast<const uint8_t *>(s2), len2);
}

#endif  // LLVM_FUZZER_DEFINES_SANITIZER_WEAK_HOOOKS
}  // extern "C"
