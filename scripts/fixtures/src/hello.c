/* Basic C fixture: libc calls through the PLT, a switch (jump table),
 * recursion, function pointers, static data and strings. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int counter;
const char *const greeting = "Hello, dasm!";
static const char *names[] = { "alpha", "beta", "gamma", "delta" };

static int fib(int n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }

__attribute__((noinline)) static int classify(int x) {
    switch (x) {
    case 0: return 10;
    case 1: return 21;
    case 2: return 32;
    case 3: return 43;
    case 4: return 54;
    case 5: return 65;
    case 6: return 76;
    default: return -1;
    }
}

__attribute__((noreturn)) static void die(const char *msg) {
    fprintf(stderr, "fatal: %s\n", msg);
    exit(2);
}

typedef int (*op_t)(int);
static int twice(int v) { return v * 2; }
static int square(int v) { return v * v; }

int main(int argc, char **argv) {
    op_t ops[2] = { twice, square };
    if (argc > 5) die("too many arguments");
    for (int i = 0; i < argc; i++) {
        counter += ops[i & 1](classify(i)) + (int)strlen(argv[i]);
    }
    printf("%s %s %d %d\n", greeting, names[argc & 3], counter, fib(argc + 5));
    return 0;
}
