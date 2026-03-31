/* indirect_jump.c - Test binary for indirect jump resolution */
#include <stdio.h>

void target_a(void) {
    printf("Target A\n");
}

void target_b(void) {
    printf("Target B\n");
}

int main(int argc, char *argv[]) {
    void (*func_ptr)(void);

    if (argc > 1) {
        func_ptr = target_a;
    } else {
        func_ptr = target_b;
    }

    func_ptr();  /* Indirect call */
    return 0;
}
