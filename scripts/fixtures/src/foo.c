/* Shared-library fixture: exported API, a constructor, PLT call to libc. */
#include <stdio.h>
#include <string.h>

int foo_counter;

__attribute__((constructor)) static void foo_init(void) { foo_counter = 1; }

int foo_add(int a, int b) { return a + b; }

size_t foo_describe(char *out, size_t n, int v) {
    int w = snprintf(out, n, "foo(%d)", v);
    return w < 0 ? 0 : strlen(out);
}
