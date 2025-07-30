CC ?= clang
CFLAGS ?= -w # -fsanitize=address -fsanitize=undefined -fsanitize=fuzzer
LDFLAGS ?= -I .  # $(LIB_FUZZING_ENGINE)
LIBS ?=

.PHONY: clean test

vuln: main.c vuln.c
	$(CC) $(CFLAGS) -o vuln main.c vuln.c $(LIBS)

test: vuln.c tests/test_vuln.c
	$(CC) $(CFLAGS) -o test_suite tests/test_vuln.c vuln.c $(LIBS)
	./test_suite

clean:
	rm -f vuln test_suite *.o