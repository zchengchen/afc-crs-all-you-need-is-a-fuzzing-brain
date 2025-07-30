#include <stdio.h>

#include "vuln.h"

int main (int argc, char ** argv) {
    person_info_t person = {};
    if (argc == 2) {
        int count = person_info_parse_file(&person, argv[1]);
        printf("The person's name is: %s\n", person.name);
    }
    return 0;
}