/*
 * Minimal bare-metal startup for running code under QEMU (mps2-an386 / mps2-an505).
 * Output and the exit status go through Arm semihosting, so QEMU's exit status is the result.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

int main(void);

extern uint32_t _sidata, _sdata, _edata, _sbss, _ebss, _estack;

#define SYS_WRITE0 0x04
#define SYS_EXIT 0x18
#define ADP_Stopped_ApplicationExit 0x20026
#define ADP_Stopped_RunTimeErrorUnknown 0x20023

static uint32_t semihost(uint32_t op, uint32_t arg) {
    register uint32_t r0 __asm__("r0") = op;
    register uint32_t r1 __asm__("r1") = arg;
    __asm__ volatile("bkpt 0xab" : "+r"(r0) : "r"(r1) : "memory");
    return r0;
}

void semihost_puts(const char *s) {
    semihost(SYS_WRITE0, (uint32_t)s);
}

void __attribute__((noreturn)) semihost_exit(bool ok) {
    semihost(SYS_EXIT, ok ? ADP_Stopped_ApplicationExit : ADP_Stopped_RunTimeErrorUnknown);
    for (;;);
}

void Default_Handler(void) {
    semihost_puts("FAULT\n");
    semihost_exit(false);
}

void Reset_Handler(void) {
#ifdef __ARM_FP
    // Grant full access to CP10/CP11 so FPU instructions don't fault.
    *(volatile uint32_t *)0xE000ED88 |= 0xFU << 20;
    __asm__ volatile("dsb\n\tisb");
#endif
    for (uint32_t *src = &_sidata, *dst = &_sdata; dst < &_edata;) {
        *dst++ = *src++;
    }
    for (uint32_t *dst = &_sbss; dst < &_ebss;) {
        *dst++ = 0;
    }
    semihost_exit(main() == 0);
}

__attribute__((section(".isr_vector"), used))
static void (*const vectors[16])(void) = {
    (void (*)(void))&_estack, Reset_Handler,
    Default_Handler, Default_Handler, Default_Handler, Default_Handler, Default_Handler, Default_Handler,
    0, 0, 0, Default_Handler, Default_Handler, 0, Default_Handler, Default_Handler,
};

// No C library is linked; these are the only libc functions the library and tests need.
// Built with -fno-tree-loop-distribute-patterns so GCC doesn't turn the loops back into calls.
// Aligned buffers (all of the library's) are handled a word at a time, like a real libc, so that
// benchmark instruction counts are not inflated by byte-wise copies.
void *memcpy(void *dst, const void *src, size_t n) {
    uint8_t *d = dst;
    const uint8_t *s = src;
    if ((((uintptr_t)d | (uintptr_t)s) & 3) == 0) {
        uint32_t *dw = (uint32_t *)d;
        const uint32_t *sw = (const uint32_t *)s;
        for (; n >= 16; n -= 16, dw += 4, sw += 4) {
            uint32_t a = sw[0], b = sw[1], c = sw[2], e = sw[3];
            dw[0] = a; dw[1] = b; dw[2] = c; dw[3] = e;
        }
        for (; n >= 4; n -= 4) *dw++ = *sw++;
        d = (uint8_t *)dw;
        s = (const uint8_t *)sw;
    }
    while (n--) *d++ = *s++;
    return dst;
}

void *memset(void *dst, int c, size_t n) {
    uint8_t *d = dst;
    if (((uintptr_t)d & 3) == 0) {
        uint32_t w = (uint8_t)c * 0x01010101U;
        uint32_t *dw = (uint32_t *)d;
        for (; n >= 16; n -= 16, dw += 4) {
            dw[0] = w; dw[1] = w; dw[2] = w; dw[3] = w;
        }
        for (; n >= 4; n -= 4) *dw++ = w;
        d = (uint8_t *)dw;
    }
    while (n--) *d++ = (uint8_t)c;
    return dst;
}

int memcmp(const void *a, const void *b, size_t n) {
    const uint8_t *x = a, *y = b;
    for (; n--; x++, y++) {
        if (*x != *y) return *x - *y;
    }
    return 0;
}
