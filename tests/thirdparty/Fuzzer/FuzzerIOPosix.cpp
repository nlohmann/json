//===- FuzzerIOPosix.cpp - IO utils for Posix. ----------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// IO functions implementation using Posix API.
//===----------------------------------------------------------------------===//
#include "FuzzerDefs.h"
#if LIBFUZZER_POSIX

#include "FuzzerExtFunctions.h"
#include "FuzzerIO.h"
#include <cstdarg>
#include <cstdio>
#include <dirent.h>
#include <fstream>
#include <iterator>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace fuzzer {

bool IsFile(const std::string &Path) {
  struct stat St;
  if (stat(Path.c_str(), &St))
    return false;
  return S_ISREG(St.st_mode);
}

void ListFilesInDirRecursive(const std::string &Dir, long *Epoch,
                             std::vector<std::string> *V, bool TopDir) {
  auto E = GetEpoch(Dir);
  if (Epoch)
    if (E && *Epoch >= E) return;

  DIR *D = opendir(Dir.c_str());
  if (!D) {
    Printf("No such directory: %s; exiting\n", Dir.c_str());
    exit(1);
  }
  while (auto E = readdir(D)) {
    std::string Path = DirPlusFile(Dir, E->d_name);
    if (E->d_type == DT_REG || E->d_type == DT_LNK)
      V->push_back(Path);
    else if (E->d_type == DT_DIR && *E->d_name != '.')
      ListFilesInDirRecursive(Path, Epoch, V, false);
  }
  closedir(D);
  if (Epoch && TopDir)
    *Epoch = E;
}

char GetSeparator() {
  return '/';
}

FILE* OpenFile(int Fd, const char* Mode) {
  return fdopen(Fd, Mode);
}

int CloseFile(int fd) {
  return close(fd);
}

int DuplicateFile(int Fd) {
  return dup(Fd);
}

void RemoveFile(const std::string &Path) {
  unlink(Path.c_str());
}

std::string DirName(const std::string &FileName) {
  char *Tmp = new char[FileName.size() + 1];
  memcpy(Tmp, FileName.c_str(), FileName.size() + 1);
  std::string Res = dirname(Tmp);
  delete [] Tmp;
  return Res;
}

}  // namespace fuzzer

#endif // LIBFUZZER_POSIX
