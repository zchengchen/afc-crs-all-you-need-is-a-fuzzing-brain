#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

#include "vuln.h"

static const char * const name_str = "name:";
/*
 * This function is obviously broken
 */
bool person_info_parse_file(person_info_t * person_info, const char * const in) {
    int last_pos = 0;
    
    int name_strlen = strlen(name_str);
    // Ensure 'name:' is there
    for (int i = 0; i < name_strlen; i++) {
        if (in[i] != name_str[i]) {
            return false;
        }
        last_pos = i;
    }

    last_pos++; // Move to after semicolon

    for (; isspace(in[last_pos]); last_pos++);

    // The bug is THE LINE BELOW THIS LINE
    strcpy(person_info->name, &in[last_pos]);

    return true;
}