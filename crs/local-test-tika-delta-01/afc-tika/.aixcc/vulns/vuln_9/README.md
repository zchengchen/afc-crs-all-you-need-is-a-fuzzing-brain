# Vuln 9

This enables a backdoor command injection vulnerability that is
triggered by metadata in an html file that also contains an embedded jpeg.

This should be difficult to find and patch because of the stack depth and because
there is no new ProcessBuilder in the patch. 