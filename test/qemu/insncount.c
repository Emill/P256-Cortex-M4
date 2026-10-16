/*
 * QEMU TCG plugin: counts executed guest instructions and hands the running total to the guest.
 *
 * Whenever the guest calls qemu_insn_count() (a naked function that only returns), this plugin
 * writes the count of instructions executed so far into r0:r1, so the call returns it as a uint64_t.
 * QEMU does not model the DWT cycle counter, so instruction counts stand in for cycles.
 */

#include <stdlib.h>
#include <string.h>
#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define MARKER "qemu_insn_count"

static struct qemu_plugin_scoreboard *counts;
static struct qemu_plugin_register *reg_r0, *reg_r1;

static void vcpu_init(unsigned int vcpu_index, void *udata) {
    GArray *regs = qemu_plugin_get_registers();
    for (guint i = 0; i < regs->len; i++) {
        qemu_plugin_reg_descriptor *r = &g_array_index(regs, qemu_plugin_reg_descriptor, i);
        if (!strcmp(r->name, "r0")) reg_r0 = r->handle;
        if (!strcmp(r->name, "r1")) reg_r1 = r->handle;
    }
    g_array_free(regs, true);
}

static void on_marker(unsigned int vcpu_index, void *udata) {
    uint64_t n = qemu_plugin_u64_get(qemu_plugin_scoreboard_u64(counts), vcpu_index);
    uint32_t lo = (uint32_t)n, hi = (uint32_t)(n >> 32);
    GByteArray *buf = g_byte_array_new();
    g_byte_array_append(buf, (const guint8 *)&lo, 4); // host and target are both little endian
    qemu_plugin_write_register(reg_r0, buf);
    g_byte_array_set_size(buf, 0);
    g_byte_array_append(buf, (const guint8 *)&hi, 4);
    qemu_plugin_write_register(reg_r1, buf);
    g_byte_array_free(buf, true);
}

static void tb_trans(struct qemu_plugin_tb *tb, void *udata) {
    size_t n = qemu_plugin_tb_n_insns(tb);
    for (size_t i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(insn, QEMU_PLUGIN_INLINE_ADD_U64,
                                                            qemu_plugin_scoreboard_u64(counts), 1);
        // The marker is only ever entered by a call, which always starts a new translation block.
        const char *sym = qemu_plugin_insn_symbol(insn);
        if (i == 0 && sym && !strcmp(sym, MARKER)) {
            qemu_plugin_register_vcpu_insn_exec_cb(insn, on_marker, QEMU_PLUGIN_CB_RW_REGS, NULL);
        }
    }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                                           int argc, char **argv) {
    counts = qemu_plugin_scoreboard_new(sizeof(uint64_t));
    qemu_plugin_register_vcpu_init_cb(id, vcpu_init, NULL);
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans, NULL);
    return 0;
}
