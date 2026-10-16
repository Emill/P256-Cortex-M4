#include <stdbool.h>
#include <stdint.h>
#include <nrf52.h>
#include <nrf52_bitfields.h>

// Build with p256_bench.c instead of tests.c and nrf52_tests_main.c, run, then read
// bench_cycles in the debugger: keygen, sign, verify, [vfy_prepare, vfy_prepared,] ecdh, decompress.
// The bracketed entries are only present when include_p256_verify_prepared is enabled.

bool p256_bench(void (*report)(const char *name, uint32_t count));

volatile uint32_t bench_cycles[7];
static uint32_t bench_index;

uint32_t p256_bench_counter(void) {
    return DWT->CYCCNT;
}

static void report(const char *name, uint32_t count) {
    (void)name;
    if (bench_index < 7) {
        bench_cycles[bench_index++] = count;
    }
}

int main() {
    NRF_NVMC->ICACHECNF = NVMC_ICACHECNF_CACHEEN_Enabled << NVMC_ICACHECNF_CACHEEN_Pos;
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT = 0;
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
    return p256_bench(report) ? 0 : 1;
}
