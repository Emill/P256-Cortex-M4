#include <stdbool.h>

bool run_tests(void);
void semihost_puts(const char *s);

int main(void) {
    bool ok = run_tests();
    semihost_puts(ok ? "PASS\n" : "FAIL\n");
    return ok ? 0 : 1;
}
