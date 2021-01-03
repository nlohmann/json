//===- FuzzerMerge.cpp - merging corpora ----------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// Merging corpora.
//===----------------------------------------------------------------------===//

#include "FuzzerInternal.h"
#include "FuzzerIO.h"
#include "FuzzerMerge.h"
#include "FuzzerTracePC.h"
#include "FuzzerUtil.h"

#include <fstream>
#include <iterator>
#include <sstream>

namespace fuzzer {

bool Merger::Parse(const std::string &Str, bool ParseCoverage) {
  std::istringstream SS(Str);
  return Parse(SS, ParseCoverage);
}

void Merger::ParseOrExit(std::istream &IS, bool ParseCoverage) {
  if (!Parse(IS, ParseCoverage)) {
    Printf("MERGE: failed to parse the control file (unexpected error)\n");
    exit(1);
  }
}

// The control file example:
//
// 3 # The number of inputs
// 1 # The number of inputs in the first corpus, <= the previous number
// file0
// file1
// file2  # One file name per line.
// STARTED 0 123  # FileID, file size
// DONE 0 1 4 6 8  # FileID COV1 COV2 ...
// STARTED 1 456  # If DONE is missing, the input crashed while processing.
// STARTED 2 567
// DONE 2 8 9
bool Merger::Parse(std::istream &IS, bool ParseCoverage) {
  LastFailure.clear();
  std::string Line;

  // Parse NumFiles.
  if (!std::getline(IS, Line, '\n')) return false;
  std::istringstream L1(Line);
  size_t NumFiles = 0;
  L1 >> NumFiles;
  if (NumFiles == 0 || NumFiles > 10000000) return false;

  // Parse NumFilesInFirstCorpus.
  if (!std::getline(IS, Line, '\n')) return false;
  std::istringstream L2(Line);
  NumFilesInFirstCorpus = NumFiles + 1;
  L2 >> NumFilesInFirstCorpus;
  if (NumFilesInFirstCorpus > NumFiles) return false;

  // Parse file names.
  Files.resize(NumFiles);
  for (size_t i = 0; i < NumFiles; i++)
    if (!std::getline(IS, Files[i].Name, '\n'))
      return false;

  // Parse STARTED and DONE lines.
  size_t ExpectedStartMarker = 0;
  const size_t kInvalidStartMarker = -1;
  size_t LastSeenStartMarker = kInvalidStartMarker;
  while (std::getline(IS, Line, '\n')) {
    std::istringstream ISS1(Line);
    std::string Marker;
    size_t N;
    ISS1 >> Marker;
    ISS1 >> N;
    if (Marker == "STARTED") {
      // STARTED FILE_ID FILE_SIZE
      if (ExpectedStartMarker != N)
        return false;
      ISS1 >> Files[ExpectedStartMarker].Size;
      LastSeenStartMarker = ExpectedStartMarker;
      assert(ExpectedStartMarker < Files.size());
      ExpectedStartMarker++;
    } else if (Marker == "DONE") {
      // DONE FILE_SIZE COV1 COV2 COV3 ...
      size_t CurrentFileIdx = N;
      if (CurrentFileIdx != LastSeenStartMarker)
        return false;
      LastSeenStartMarker = kInvalidStartMarker;
      if (ParseCoverage) {
        auto &V = Files[CurrentFileIdx].Features;
        V.clear();
        while (ISS1 >> std::hex >> N)
          V.push_back(N);
        std::sort(V.begin(), V.end());
      }
    } else {
      return false;
    }
  }
  if (LastSeenStartMarker != kInvalidStartMarker)
    LastFailure = Files[LastSeenStartMarker].Name;

  FirstNotProcessedFile = ExpectedStartMarker;
  return true;
}

// Decides which files need to be merged (add thost to NewFiles).
// Returns the number of new features added.
size_t Merger::Merge(std::vector<std::string> *NewFiles) {
  NewFiles->clear();
  assert(NumFilesInFirstCorpus <= Files.size());
  std::set<uint32_t> AllFeatures;

  // What features are in the initial corpus?
  for (size_t i = 0; i < NumFilesInFirstCorpus; i++) {
    auto &Cur = Files[i].Features;
    AllFeatures.insert(Cur.begin(), Cur.end());
  }
  size_t InitialNumFeatures = AllFeatures.size();

  // Remove all features that we already know from all other inputs.
  for (size_t i = NumFilesInFirstCorpus; i < Files.size(); i++) {
    auto &Cur = Files[i].Features;
    std::vector<uint32_t> Tmp;
    std::set_difference(Cur.begin(), Cur.end(), AllFeatures.begin(),
                        AllFeatures.end(), std::inserter(Tmp, Tmp.begin()));
    Cur.swap(Tmp);
  }

  // Sort. Give preference to
  //   * smaller files
  //   * files with more features.
  std::sort(Files.begin() + NumFilesInFirstCorpus, Files.end(),
            [&](const MergeFileInfo &a, const MergeFileInfo &b) -> bool {
              if (a.Size != b.Size)
                return a.Size < b.Size;
              return a.Features.size() > b.Features.size();
            });

  // One greedy pass: add the file's features to AllFeatures.
  // If new features were added, add this file to NewFiles.
  for (size_t i = NumFilesInFirstCorpus; i < Files.size(); i++) {
    auto &Cur = Files[i].Features;
    // Printf("%s -> sz %zd ft %zd\n", Files[i].Name.c_str(),
    //       Files[i].Size, Cur.size());
    size_t OldSize = AllFeatures.size();
    AllFeatures.insert(Cur.begin(), Cur.end());
    if (AllFeatures.size() > OldSize)
      NewFiles->push_back(Files[i].Name);
  }
  return AllFeatures.size() - InitialNumFeatures;
}

// Inner process. May crash if the target crashes.
void Fuzzer::CrashResistantMergeInternalStep(const std::string &CFPath) {
  Printf("MERGE-INNER: using the control file '%s'\n", CFPath.c_str());
  Merger M;
  std::ifstream IF(CFPath);
  M.ParseOrExit(IF, false);
  IF.close();
  if (!M.LastFailure.empty())
    Printf("MERGE-INNER: '%s' caused a failure at the previous merge step\n",
           M.LastFailure.c_str());

  Printf("MERGE-INNER: %zd total files;"
         " %zd processed earlier; will process %zd files now\n",
         M.Files.size(), M.FirstNotProcessedFile,
         M.Files.size() - M.FirstNotProcessedFile);

  std::ofstream OF(CFPath, std::ofstream::out | std::ofstream::app);
  for (size_t i = M.FirstNotProcessedFile; i < M.Files.size(); i++) {
    auto U = FileToVector(M.Files[i].Name);
    if (U.size() > MaxInputLen) {
      U.resize(MaxInputLen);
      U.shrink_to_fit();
    }
    std::ostringstream StartedLine;
    // Write the pre-run marker.
    OF << "STARTED " << std::dec << i << " " << U.size() << "\n";
    OF.flush();  // Flush is important since ExecuteCommand may crash.
    // Run.
    TPC.ResetMaps();
    ExecuteCallback(U.data(), U.size());
    // Collect coverage.
    std::set<size_t> Features;
    TPC.CollectFeatures([&](size_t Feature) -> bool {
      Features.insert(Feature);
      return true;
    });
    // Show stats.
    TotalNumberOfRuns++;
    if (!(TotalNumberOfRuns & (TotalNumberOfRuns - 1)))
      PrintStats("pulse ");
    // Write the post-run marker and the coverage.
    OF << "DONE " << i;
    for (size_t F : Features)
      OF << " " << std::hex << F;
    OF << "\n";
  }
}

// Outer process. Does not call the target code and thus sohuld not fail.
void Fuzzer::CrashResistantMerge(const std::vector<std::string> &Args,
                                 const std::vector<std::string> &Corpora) {
  if (Corpora.size() <= 1) {
    Printf("Merge requires two or more corpus dirs\n");
    return;
  }
  std::vector<std::string> AllFiles;
  ListFilesInDirRecursive(Corpora[0], nullptr, &AllFiles, /*TopDir*/true);
  size_t NumFilesInFirstCorpus = AllFiles.size();
  for (size_t i = 1; i < Corpora.size(); i++)
    ListFilesInDirRecursive(Corpora[i], nullptr, &AllFiles, /*TopDir*/true);
  Printf("MERGE-OUTER: %zd files, %zd in the initial corpus\n",
         AllFiles.size(), NumFilesInFirstCorpus);
  std::string CFPath =
      "libFuzzerTemp." + std::to_string(GetPid()) + ".txt";
  // Write the control file.
  RemoveFile(CFPath);
  std::ofstream ControlFile(CFPath);
  ControlFile << AllFiles.size() << "\n";
  ControlFile << NumFilesInFirstCorpus << "\n";
  for (auto &Path: AllFiles)
    ControlFile << Path << "\n";
  ControlFile.close();

  // Execute the inner process untill it passes.
  // Every inner process should execute at least one input.
  std::string BaseCmd = CloneArgsWithoutX(Args, "keep-all-flags");
  for (size_t i = 1; i <= AllFiles.size(); i++) {
    Printf("MERGE-OUTER: attempt %zd\n", i);
    auto ExitCode =
        ExecuteCommand(BaseCmd + " -merge_control_file=" + CFPath);
    if (!ExitCode) {
      Printf("MERGE-OUTER: succesfull in %zd attempt(s)\n", i);
      break;
    }
  }
  // Read the control file and do the merge.
  Merger M;
  std::ifstream IF(CFPath);
  M.ParseOrExit(IF, true);
  IF.close();
  std::vector<std::string> NewFiles;
  size_t NumNewFeatures = M.Merge(&NewFiles);
  Printf("MERGE-OUTER: %zd new files with %zd new features added\n",
         NewFiles.size(), NumNewFeatures);
  for (auto &F: NewFiles)
    WriteToOutputCorpus(FileToVector(F));
  // We are done, delete the control file.
  RemoveFile(CFPath);
}

} // namespace fuzzer
