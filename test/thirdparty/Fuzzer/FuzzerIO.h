//===- FuzzerIO.h - Internal header for IO utils ----------------*- C++ -* ===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// IO interface.
//===----------------------------------------------------------------------===//

#ifndef LLVM_FUZZER_IO_H
#define LLVM_FUZZER_IO_H

#include "FuzzerDefs.h"

namespace fuzzer {

long GetEpoch(const std::string &Path);

Unit FileToVector(const std::string &Path, size_t MaxSize = 0,
                  bool ExitOnError = true);

std::string FileToString(const std::string &Path);

void CopyFileToErr(const std::string &Path);

void WriteToFile(const Unit &U, const std::string &Path);

void ReadDirToVectorOfUnits(const char *Path, std::vector<Unit> *V,
                            long *Epoch, size_t MaxSize, bool ExitOnError);

// Returns "Dir/FileName" or equivalent for the current OS.
std::string DirPlusFile(const std::string &DirPath,
                        const std::string &FileName);

// Returns the name of the dir, similar to the 'dirname' utility.
std::string DirName(const std::string &FileName);

void DupAndCloseStderr();

void CloseStdout();

void Printf(const char *Fmt, ...);

// Platform specific functions:
bool IsFile(const std::string &Path);

void ListFilesInDirRecursive(const std::string &Dir, long *Epoch,
                             std::vector<std::string> *V, bool TopDir);

char GetSeparator();

FILE* OpenFile(int Fd, const char *Mode);

int CloseFile(int Fd);

int DuplicateFile(int Fd);

void RemoveFile(const std::string &Path);

}  // namespace fuzzer

#endif  // LLVM_FUZZER_IO_H
