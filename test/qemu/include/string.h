/* The toolchain ships no C library; startup.c implements these. */
#ifndef QEMU_TEST_STRING_H
#define QEMU_TEST_STRING_H
#include <stddef.h>
void *memcpy(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);
#endif
