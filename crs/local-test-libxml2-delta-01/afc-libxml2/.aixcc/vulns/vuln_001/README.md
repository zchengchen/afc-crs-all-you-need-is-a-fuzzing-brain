## Name

Vuln 001 libxml2

## Overview

``libxml2`` is a robust and widely used library for parsing XML and HTML documents. It includes support for handling HTML specifically through its HTML parser, which is designed to deal with the quirks and complexities of real-world HTML, including non-well-formed documents. With ``libxml2``, you can load, parse, and manipulate HTML documents programmatically using its tree-based DOM-like API. Additionally, the library provides functions for navigating and modifying the document tree, making it a powerful tool for web scraping, data extraction, or transforming HTML content. Its HTML parser can also automatically fix common errors in malformed HTML, ensuring broader compatibility.

## Vulnerability

The ``libxml2`` library is capable of parsing HTML content. This vulnerability is injected into this parsing logic. At the beginning of the handler there is a check for a comment. This was handled by a generic comment parsing function but I added a special handler for the top comment. Additionally, I added a special state for handling ``%`` encoded hexadecimal values. This forces a jump to the ``next_chunk`` label. There is a memcpy that checks to copies the comment data up to that point. The check to ensure that it is within the bounds of the new buffer is modified to only check if this current chunk length is within the bounds, allowing a heap based buffer overflow.

## Example crash

```
=================================================================
==14==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x515000000775 at pc 0x562b34ae6164 bp 0x7ffef8143790 sp 0x7ffef8142f50
WRITE of size 105 at 0x515000000775 thread T0
SCARINESS: 45 (multi-byte-write-heap-buffer-overflow)
    #0 0x562b34ae6163 in __asan_memcpy /src/llvm-project/compiler-rt/lib/asan/asan_interceptors_memintrinsics.cpp:63:3
    #1 0x562b34c3941f in htmlSecureComment /src/libxml2/HTMLparser.c:3591:13
    #2 0x562b34c3941f in htmlTopParseComment /src/libxml2/HTMLparser.c:3700:19
    #3 0x562b34c36716 in htmlParseDocument /src/libxml2/HTMLparser.c:4718:13
    #4 0x562b34c41272 in htmlCtxtParseDocument /src/libxml2/HTMLparser.c:6275:5
    #5 0x562b34b27a5a in LLVMFuzzerTestOneInput /src/libxml2/fuzz/html.c:51:15
    #6 0x562b349dc410 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:614:13
    #7 0x562b349c7685 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:327:6
    #8 0x562b349cd11f in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:862:9
    #9 0x562b349f83c2 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #10 0x7f510e064082 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 0702430aef5fa3dda43986563e9ffcc47efbd75e)
    #11 0x562b349bf86d in _start (/out/html+0x1ae86d)

DEDUP_TOKEN: __asan_memcpy--htmlSecureComment--htmlTopParseComment
0x515000000775 is located 0 bytes after 501-byte region [0x515000000580,0x515000000775)
allocated by thread T0 here:
    #0 0x562b34ae81df in malloc /src/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:68:3
    #1 0x562b34b27f78 in xmlFuzzMalloc /src/libxml2/fuzz/fuzz.c:127:11
    #2 0x562b34c38754 in htmlSecureComment /src/libxml2/HTMLparser.c:3335:18
    #3 0x562b34c38754 in htmlTopParseComment /src/libxml2/HTMLparser.c:3700:19
    #4 0x562b34c36716 in htmlParseDocument /src/libxml2/HTMLparser.c:4718:13
    #5 0x562b34c41272 in htmlCtxtParseDocument /src/libxml2/HTMLparser.c:6275:5
    #6 0x562b34b27a5a in LLVMFuzzerTestOneInput /src/libxml2/fuzz/html.c:51:15
    #7 0x562b349dc410 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:614:13
    #8 0x562b349c7685 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:327:6
    #9 0x562b349cd11f in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:862:9
    #10 0x562b349f83c2 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #11 0x7f510e064082 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 0702430aef5fa3dda43986563e9ffcc47efbd75e)

DEDUP_TOKEN: __interceptor_malloc--xmlFuzzMalloc--htmlSecureComment
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/libxml2/HTMLparser.c:3591:13 in htmlSecureComment
Shadow bytes around the buggy address:
  0x515000000480: fd fd fd fd fd fd fd fd fd fd fd fa fa fa fa fa
  0x515000000500: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x515000000580: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x515000000600: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x515000000680: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x515000000700: 00 00 00 00 00 00 00 00 00 00 00 00 00 00[05]fa
  0x515000000780: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x515000000800: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x515000000880: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x515000000900: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x515000000980: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==14==ABORTING
```
