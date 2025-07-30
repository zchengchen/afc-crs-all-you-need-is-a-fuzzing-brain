#ifndef VULN_H
#define VULN_H

#include <stdbool.h>

#define MAX_STRLEN 32

typedef struct person_info_t {
    char name[MAX_STRLEN];
} person_info_t;

/**
 * Parses some input and outputs it to person_info. The in string should look something like below:
 * 
 * name: John Doe
 * 
 * Whitespace following the colon and preceding the first non-whitespace character will be stripped.
 * 
 * @param person_info The output person_info_t structure that the in parameter gets parsed to
 * @param in The string that gets parsed into person_info. 
 * @return success or failure to parse input
 */
bool person_info_parse_file(person_info_t * person_info, const char * const in);



#endif // VULN_H