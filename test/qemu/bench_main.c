#include <stdint.h>
#include <stdbool.h>

bool p256_bench(void (*report)(const char *name, uint32_t count));
void semihost_puts(const char *s);

// Returns the number of instructions executed so far: the insncount plugin writes r0:r1 on entry.
__attribute__((naked, noinline, used)) uint64_t qemu_insn_count(void) {
    __asm__ volatile("bx lr");
}

uint32_t p256_bench_counter(void) {
    return (uint32_t)qemu_insn_count();
}

static void report(const char *name, uint32_t count) {
    char line[40], digits[10];
    int n = 0, d = 0;
    while (*name) line[n++] = *name++;
    do line[n++] = ' '; while (n < 12);
    do digits[d++] = '0' + count % 10; while (count /= 10);
    while (d) line[n++] = digits[--d];
    line[n++] = '\n';
    line[n] = 0;
    semihost_puts(line);
}

int main(void) {
    bool ok = p256_bench(report);
    semihost_puts(ok ? "" : "FAIL\n");
    return ok ? 0 : 1;
}
