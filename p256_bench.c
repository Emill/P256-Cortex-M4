/*
 * Measures the operations in the README's performance table.
 *
 * The platform provides p256_bench_counter(): the DWT cycle counter on hardware (see
 * nrf52_bench_main.c), or an instruction counter under QEMU (see test/qemu/bench_main.c).
 * Each result is passed to the report callback; false is returned if any operation fails.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "p256-cortex-m4.h"

uint32_t p256_bench_counter(void);

bool p256_bench(void (*report)(const char *name, uint32_t count)) {
    // Fixed inputs; all scalars are in the range 1 to n-1.
    static const uint32_t priv[8] = {0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x66666666, 0x77777777, 0x88888888};
    static const uint32_t priv2[8] = {0x12345678, 0x9abcdef0, 0x0fedcba9, 0x87654321, 0x13579bdf, 0x2468ace0, 0x0eca8642, 0x7db97531};
    static const uint32_t k[8] = {0x89abcdef, 0x01234567, 0xfedcba98, 0x76543210, 0x0f1e2d3c, 0x4b5a6978, 0x8796a5b4, 0x3c2d1e0f};
    static const uint8_t hash[32] = {
        0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65, 0x9a, 0x2f, 0xea, 0xa0, 0xc5, 0x5a, 0xd0, 0x15,
        0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0x0b, 0x82, 0x2c, 0xd1, 0x5d, 0x6c, 0x15, 0xb0, 0xf0, 0x0a, 0x08
    };
    uint32_t pub_x[8], pub_y[8], r[8], s[8], x[8], y[8];
    uint8_t shared[32], compressed[33];
    uint32_t t;
    bool ok;

    t = p256_bench_counter();
    ok = p256_keygen(pub_x, pub_y, priv);
    report("keygen", p256_bench_counter() - t);
    if (!ok) return false;

    t = p256_bench_counter();
    ok = p256_sign(r, s, hash, sizeof(hash), priv, k);
    report("sign", p256_bench_counter() - t);
    if (!ok) return false;

    t = p256_bench_counter();
    ok = p256_verify(pub_x, pub_y, hash, sizeof(hash), r, s);
    report("verify", p256_bench_counter() - t);
    if (!ok) return false;

#if include_p256_verify_prepared
    struct VerifyPrecomp ctx;
    t = p256_bench_counter();
    ok = p256_verify_prepare(&ctx, pub_x, pub_y);
    report("vfy_prepare", p256_bench_counter() - t);
    if (!ok) return false;

    t = p256_bench_counter();
    ok = p256_verify_prepared(&ctx, hash, sizeof(hash), r, s);
    report("vfy_prepared", p256_bench_counter() - t);
    if (!ok) return false;
#endif

    t = p256_bench_counter();
    ok = p256_ecdh_calc_shared_secret(shared, priv2, pub_x, pub_y);
    report("ecdh", p256_bench_counter() - t);
    if (!ok) return false;

    p256_point_to_octet_string_compressed(compressed, pub_x, pub_y);
    t = p256_bench_counter();
    ok = p256_octet_string_to_point(x, y, compressed, sizeof(compressed));
    report("decompress", p256_bench_counter() - t);
    return ok && memcmp(y, pub_y, 32) == 0;
}
