/* File 2 of the merge demo: defines the symbols main_part.c needs. */
static int local_state = 9;
int scale = 3;

int helper(int x) {
    return x * scale + local_state;
}
