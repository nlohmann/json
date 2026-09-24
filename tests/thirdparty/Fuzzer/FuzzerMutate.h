//===- FuzzerMutate.h - Internal header for the Fuzzer ----------*- C++ -* ===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// fuzzer::MutationDispatcher
//===----------------------------------------------------------------------===//

#ifndef LLVM_FUZZER_MUTATE_H
#define LLVM_FUZZER_MUTATE_H

#include "FuzzerDefs.h"
#include "FuzzerDictionary.h"
#include "FuzzerRandom.h"

namespace fuzzer {

class MutationDispatcher {
public:
  MutationDispatcher(Random &Rand, const FuzzingOptions &Options);
  ~MutationDispatcher() {}
  /// Indicate that we are about to start a new sequence of mutations.
  void StartMutationSequence();
  /// Print the current sequence of mutations.
  void PrintMutationSequence();
  /// Indicate that the current sequence of mutations was successfull.
  void RecordSuccessfulMutationSequence();
  /// Mutates data by invoking user-provided mutator.
  size_t Mutate_Custom(uint8_t *Data, size_t Size, size_t MaxSize);
  /// Mutates data by invoking user-provided crossover.
  size_t Mutate_CustomCrossOver(uint8_t *Data, size_t Size, size_t MaxSize);
  /// Mutates data by shuffling bytes.
  size_t Mutate_ShuffleBytes(uint8_t *Data, size_t Size, size_t MaxSize);
  /// Mutates data by erasing bytes.
  size_t Mutate_EraseBytes(uint8_t *Data, size_t Size, size_t MaxSize);
  /// Mutates data by inserting a byte.
  size_t Mutate_InsertByte(uint8_t *Data, size_t Size, size_t MaxSize);
  /// Mutates data by inserting several repeated bytes.
  size_t Mutate_InsertRepeatedBytes(uint8_t *Data, size_t Size, size_t MaxSize);
  /// Mutates data by chanding one byte.
  size_t Mutate_ChangeByte(uint8_t *Data, size_t Size, size_t MaxSize);
  /// Mutates data by chanding one bit.
  size_t Mutate_ChangeBit(uint8_t *Data, size_t Size, size_t MaxSize);
  /// Mutates data by copying/inserting a part of data into a different place.
  size_t Mutate_CopyPart(uint8_t *Data, size_t Size, size_t MaxSize);

  /// Mutates data by adding a word from the manual dictionary.
  size_t Mutate_AddWordFromManualDictionary(uint8_t *Data, size_t Size,
                                            size_t MaxSize);

  /// Mutates data by adding a word from the temporary automatic dictionary.
  size_t Mutate_AddWordFromTemporaryAutoDictionary(uint8_t *Data, size_t Size,
                                                   size_t MaxSize);

  /// Mutates data by adding a word from the TORC.
  size_t Mutate_AddWordFromTORC(uint8_t *Data, size_t Size, size_t MaxSize);

  /// Mutates data by adding a word from the persistent automatic dictionary.
  size_t Mutate_AddWordFromPersistentAutoDictionary(uint8_t *Data, size_t Size,
                                                    size_t MaxSize);

  /// Tries to find an ASCII integer in Data, changes it to another ASCII int.
  size_t Mutate_ChangeASCIIInteger(uint8_t *Data, size_t Size, size_t MaxSize);
  /// Change a 1-, 2-, 4-, or 8-byte integer in interesting ways.
  size_t Mutate_ChangeBinaryInteger(uint8_t *Data, size_t Size, size_t MaxSize);

  /// CrossOver Data with some other element of the corpus.
  size_t Mutate_CrossOver(uint8_t *Data, size_t Size, size_t MaxSize);

  /// Applies one of the configured mutations.
  /// Returns the new size of data which could be up to MaxSize.
  size_t Mutate(uint8_t *Data, size_t Size, size_t MaxSize);
  /// Applies one of the default mutations. Provided as a service
  /// to mutation authors.
  size_t DefaultMutate(uint8_t *Data, size_t Size, size_t MaxSize);

  /// Creates a cross-over of two pieces of Data, returns its size.
  size_t CrossOver(const uint8_t *Data1, size_t Size1, const uint8_t *Data2,
                   size_t Size2, uint8_t *Out, size_t MaxOutSize);

  void AddWordToManualDictionary(const Word &W);

  void AddWordToAutoDictionary(DictionaryEntry DE);
  void ClearAutoDictionary();
  void PrintRecommendedDictionary();

  void SetCorpus(const InputCorpus *Corpus) { this->Corpus = Corpus; }

  Random &GetRand() { return Rand; }

private:

  struct Mutator {
    size_t (MutationDispatcher::*Fn)(uint8_t *Data, size_t Size, size_t Max);
    const char *Name;
  };

  size_t AddWordFromDictionary(Dictionary &D, uint8_t *Data, size_t Size,
                               size_t MaxSize);
  size_t MutateImpl(uint8_t *Data, size_t Size, size_t MaxSize,
                    const std::vector<Mutator> &Mutators);

  size_t InsertPartOf(const uint8_t *From, size_t FromSize, uint8_t *To,
                      size_t ToSize, size_t MaxToSize);
  size_t CopyPartOf(const uint8_t *From, size_t FromSize, uint8_t *To,
                    size_t ToSize);
  size_t ApplyDictionaryEntry(uint8_t *Data, size_t Size, size_t MaxSize,
                              DictionaryEntry &DE);

  template <class T>
  DictionaryEntry MakeDictionaryEntryFromCMP(T Arg1, T Arg2,
                                             const uint8_t *Data, size_t Size);

  Random &Rand;
  const FuzzingOptions &Options;

  // Dictionary provided by the user via -dict=DICT_FILE.
  Dictionary ManualDictionary;
  // Temporary dictionary modified by the fuzzer itself,
  // recreated periodically.
  Dictionary TempAutoDictionary;
  // Persistent dictionary modified by the fuzzer, consists of
  // entries that led to successfull discoveries in the past mutations.
  Dictionary PersistentAutoDictionary;

  std::vector<Mutator> CurrentMutatorSequence;
  std::vector<DictionaryEntry *> CurrentDictionaryEntrySequence;

  static const size_t kCmpDictionaryEntriesDequeSize = 16;
  DictionaryEntry CmpDictionaryEntriesDeque[kCmpDictionaryEntriesDequeSize];
  size_t CmpDictionaryEntriesDequeIdx = 0;

  const InputCorpus *Corpus = nullptr;
  std::vector<uint8_t> MutateInPlaceHere;

  std::vector<Mutator> Mutators;
  std::vector<Mutator> DefaultMutators;
};

}  // namespace fuzzer

#endif  // LLVM_FUZZER_MUTATE_H
