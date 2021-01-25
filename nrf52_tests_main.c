#include <stdbool.h>
#include <assert.h>
#include <nrf52.h>
#include <nrf52_bitfields.h>

// run "node testgen.js > tests.c" first, with a nodejs version >= 10.4

bool run_tests(void);

int main() {
    NRF_NVMC->ICACHECNF = NVMC_ICACHECNF_CACHEEN_Enabled << NVMC_ICACHECNF_CACHEEN_Pos;
    bool res = run_tests();
    assert(res);
    return res ? 0 : 1;
}
