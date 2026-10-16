# Runs tests.c on emulated Cortex-M4 (mps2-an386) and Cortex-M33 (mps2-an505) under QEMU.
#
#   make                 default config: CPU=m4 FPU=1 DCACHE=0 MULSQR=0 FASTBASE=1 TABLES=2
#   make CPU=m33 FPU=0   any single config
#   make matrix          all 64 combinations of CPU/FPU/DCACHE/MULSQR and FASTBASE=0, or FASTBASE=1 with TABLES=2/4/8
#   EXTRA_DEFS="-Dx=1"   extra config defines, applied to any of the above
#   make bench           instruction counts per operation (p256_bench.c), for any single config
#
# Requires arm-none-eabi-gcc and qemu-system-arm; bench also needs a host C compiler and glib (pkg-config).

CPU      ?= m4
FPU      ?= 1
DCACHE   ?= 0
MULSQR   ?= 0
FASTBASE ?= 1
TABLES   ?= 2

CC   := arm-none-eabi-gcc
QEMU := qemu-system-arm
ROOT := ../..

ifeq ($(CPU),m4)
MACHINE := mps2-an386
MCPU    := cortex-m4
FPUNAME := fpv4-sp-d16
else ifeq ($(CPU),m33)
MACHINE := mps2-an505
MCPU    := cortex-m33
FPUNAME := fpv5-sp-d16
else
$(error CPU must be m4 or m33)
endif

ifeq ($(FPU),1)
ARCHFLAGS := -mcpu=$(MCPU) -mfpu=$(FPUNAME) -mfloat-abi=hard
else
ARCHFLAGS := -mcpu=$(MCPU)+nofp -mfloat-abi=soft
endif

CONFIG := $(CPU)-fpu$(FPU)-dcache$(DCACHE)-mulsqr$(MULSQR)-fastbase$(FASTBASE)-tables$(TABLES)$(subst $() ,,$(EXTRA_DEFS))
OUT    := build/$(CONFIG)
DEFS   := -Dhas_fpu=$(FPU) -Dhas_d_cache=$(DCACHE) -Duse_mul_for_sqr=$(MULSQR) -Duse_fast_p256_basemult=$(FASTBASE) \
          -Dfast_p256_basemult_tables=$(TABLES) $(EXTRA_DEFS)
CFLAGS := $(ARCHFLAGS) -mthumb -O2 -g -ffreestanding -fno-tree-loop-distribute-patterns -Wall $(DEFS) -Iinclude -I$(ROOT)
LDFLAGS := $(ARCHFLAGS) -mthumb -nostdlib -L. -T $(MACHINE).ld -Wl,--gc-sections

LIB  := $(ROOT)/p256-cortex-m4.c $(ROOT)/p256-cortex-m4-asm-gcc.S startup.c
HDRS := $(ROOT)/p256-cortex-m4.h $(ROOT)/p256-cortex-m4-config.h include/string.h
RUN  := $(QEMU) -M $(MACHINE) -nographic -semihosting-config enable=on,target=native

HOST_OS := $(shell uname)
HOSTCC  ?= $(firstword $(wildcard /usr/bin/cc) cc)
PLUGIN  := build/libinsncount.$(if $(filter Darwin,$(HOST_OS)),dylib,so)

.PHONY: test matrix bench clean

test: $(OUT)/tests.elf
	@printf '%-40s ' $(CONFIG); $(RUN) -kernel $<

bench: $(OUT)/bench.elf $(PLUGIN)
	@echo "$(CONFIG): instructions per operation (QEMU does not count cycles)"; $(RUN) -plugin $(PLUGIN) -kernel $<

$(OUT)/tests.elf: $(LIB) $(ROOT)/tests.c tests_main.c $(HDRS) $(MACHINE).ld sections.ld Makefile
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(LIB) $(ROOT)/tests.c tests_main.c -lgcc

$(OUT)/bench.elf: $(LIB) $(ROOT)/p256_bench.c bench_main.c $(HDRS) $(MACHINE).ld sections.ld Makefile
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(LIB) $(ROOT)/p256_bench.c bench_main.c -lgcc

$(PLUGIN): insncount.c Makefile
	@mkdir -p build
	$(HOSTCC) -O2 -shared -fPIC $(shell pkg-config --cflags glib-2.0) -I$(dir $(shell command -v $(QEMU)))../include \
		$(if $(filter Darwin,$(HOST_OS)),-undefined dynamic_lookup) -o $@ $<

matrix:
	@fail=0; \
	for cpu in m4 m33; do for fpu in 0 1; do for dc in 0 1; do for ms in 0 1; do for fbt in 0:2 1:2 1:4 1:8; do \
		$(MAKE) -s test CPU=$$cpu FPU=$$fpu DCACHE=$$dc MULSQR=$$ms FASTBASE=$${fbt%:*} TABLES=$${fbt#*:} || fail=$$((fail+1)); \
	done; done; done; done; done; \
	echo "failed configs: $$fail"; [ $$fail -eq 0 ]

clean:
	rm -rf build
