/* Clashes with helper_part.c (both define `helper`) and needs an undefined symbol. */
extern int missing_symbol;

int helper(int x) {
    return x + missing_symbol;
}
