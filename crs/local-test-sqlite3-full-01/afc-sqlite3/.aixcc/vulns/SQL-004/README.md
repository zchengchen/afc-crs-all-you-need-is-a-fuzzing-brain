1. ID:
SQL-004, Heap OOB Read on SQLite shell error context

2. Primary CWE:
CWE-125: Out-of-bounds Read

3. Sanitizer and Behavior
AddressSanitizer: heap-buffer-overflow

4. High-level Description of Challenge Vulnerability
This challenge was a reimplementation of a [bug found in SQLite's bug tracker](https://www.sqlite.org/src/tktview/33aa4c0de8). The problem stems from the ``sqlite3_error_offset()`` routine returning a value that is out-of-range for its input. Then, the CLI code that uses ``sqlite3_error_offset()`` fails to properly deal with the out-of-range return value. This leads to crashes for certain malformed inputs that cause out of bounds reads on the heap.

5. Optimal Patch
The SQLite developer that patched this bug previously added a check to find erroneous values for an offset value, and if it was found, just opted to print an empty string and return. So in this case it never actually prints where your error occured. This is likely a band-aid patch and more work to mitigate what's actually causing this bug should be explored and submitted as a patch.
