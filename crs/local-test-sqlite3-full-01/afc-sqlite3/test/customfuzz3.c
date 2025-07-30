/*
** This module interfaces SQLite to the Google OSS-Fuzz, fuzzer as a service.
** (https://github.com/google/oss-fuzz)
*/
#include <stddef.h>
#if !defined(_MSC_VER)
#include <stdint.h>
#endif
#include <stdio.h>
#include <string.h>
#include "sqlite3.h"
#include "shell.h"

/*
** Main entry point.  The fuzzer invokes this function with each
** fuzzed input.
*/
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  char *command = sqlite3_mprintf("%.*s", (int)size, data);
  int argc = 3;
  char *shellCmd[argc];
  shellCmd[0] = "./sqlite";
  shellCmd[1] = ":memory:";
  shellCmd[2] = command;

  shell_main(argc, shellCmd);
  sqlite3_free(command);
  return 0;
}
