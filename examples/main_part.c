/* File 1 of the merge demo: calls into helper_part.c and keeps a static of the same name. */
int shared_counter = 1;
static int local_state = 5;        /* local: must NOT be reported as multiply defined */
const char greeting[] = "hello";
int buffer[64];                    /* .bss */

extern int helper(int);            /* UND here, defined in helper_part.o */
extern int scale;                  /* UND here, defined in helper_part.o */

int entry(void) {
    return helper(shared_counter) + scale + local_state + greeting[0] + buffer[0];
}
