# Zookeeper (vuln\_2) Infinite loop in ipv6 validation

This is a vulnerability in a logging utility in MessageTracker.java 
that attempts to check the validation of an iPv6 formatted string,
counting the number of colons and comparing them to a max value.

The vulnerability itself is a failure to properly iterate over 
values in the string. A simple infinite loop created by calling 
String#indexOf without incrementing the last found index.

Exploiting this vulnerability would allow someone to craft input
that causes a Denial-of-Service (DoS), reducing the availability 
of the zookeeper service.
