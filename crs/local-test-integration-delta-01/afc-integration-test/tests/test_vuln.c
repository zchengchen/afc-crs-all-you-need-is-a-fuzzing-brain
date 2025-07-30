#include <stdio.h>
#include <string.h>

#include "../vuln.h"

// From Chromium. Returns the number of elements in an array
#define COUNT_OF(x) (sizeof(x)/sizeof(x[0]))

typedef struct {
    person_info_t person;
    bool return_code;
} test_result_t;

typedef struct {
    const char * const name;
    const char * in;
    test_result_t expected;
} input_t;

void test_result_print(const char * const name, test_result_t result) {
    printf("%s:\n", name);
    printf("\t- return code: %s\n", result.return_code ? "true" : "false");
    if (result.return_code) {
        printf("\t- person name: %s\n", result.person.name);
    }
}

void fail(input_t input, test_result_t actual) {
    printf("Failed '%s':\n", input.name);
    test_result_print("Expected", input.expected);
    test_result_print("Actual", actual);
}

bool run_test(input_t input) {   
    test_result_t actual = {};
    bool success;

    actual.return_code = person_info_parse_file(&actual.person, input.in);
    if (input.expected.return_code == actual.return_code) {
        if (actual.return_code) {
            // Success expected. Check the parsed string
            success = strcmp(input.expected.person.name, actual.person.name) == 0;
        } else {
            // Failure expected, so we succeed
            success = true;
        }
    } else {
        success = false;
    }

    if (!success) {
        fail(input, actual);
    }

    return success;
}

int main() {
    input_t inputs[] = {
        (input_t) {
            .name = "Test empty string",
            .in = "",
            .expected = (test_result_t) {
                .return_code = false
            }
        },
        (input_t) {
            .name = "Test Giberish",
            .in = "7cnh1b3v4h5of:fj38c9xh",
            .expected = (test_result_t) {
                .return_code = false
            }
        },
        (input_t) {
            .name = "Test name: string", 
            .in = "name:", 
            .expected = (test_result_t) {
                .return_code = true,
                .person = (person_info_t) {.name = ""}
            }
        },
        (input_t) {
            .name = "Test name string", 
            .in = "name", 
            .expected = (test_result_t) {
                .return_code = false,
            }
        },
        (input_t) {
            .name = "Test no whitespace",
            .in = "name:AIxCC",
            .expected = (test_result_t) {
                .return_code = true,
                .person = (person_info_t) {.name = "AIxCC"}
            }
        },
        (input_t) {
            .name = "Test with whitespace",
            .in = "name: \t\n\v\r\fAIxCC",
            .expected = (test_result_t) {
                .return_code = true,
                .person = (person_info_t) {.name = "AIxCC"}
            }
        },
    };

    bool passed = true;
    // Run tests
    for (int i = 0; i < COUNT_OF(inputs); i++) {
        passed = passed && run_test(inputs[i]);
    }

    if (passed) {
        printf("All tests pass\n");
        return 0;
    } else {
        printf("Some tests failed\n");
        return 1;
    }
}