1. ID: 
SQL-003

2. Primary CWE:
CWE-787: Out-of-bounds Write

3. Sanitizer and Behavior
AddressSanitizer: stack-buffer-overflow

4. High-level Description of Challenge Vulnerability
SQLite includes a simple implementation of the rot13 substitution cipher. For speed purposes, rot13 always quickly allocates a small output buffer, so that if the input is less than 100 bytes it may use that buffer immediately. Otherwise, it takes a slow path to allocate as much memory as necessary for the output. SQL-003 introduces an off-by-one error wherein an input of exactly 100 bytes takes the fast path. Since the rot13 implementation requires (sizeof(input) + 1) bytes to do its job, the code will now write one byte out of bounds.

5. Optimal Patch
Change the size check to correct the off-by-one error.
