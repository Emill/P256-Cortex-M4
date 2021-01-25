/*
 * Copyright (c) 2017-2021 Emil Lenngren
 * Copyright (c) 2021 Shortcut Labs AB
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef P256_CORTEX_M4_CONFIG
#define P256_CORTEX_M4_CONFIG

// To enable a flag, define to 1. To disable, define to 0.

// Algorithm inclusion settings

// See p256-cortex-m4.h to understand what functions are included for each flag.

#ifndef include_p256_verify
#define include_p256_verify 1
#endif

#ifndef include_p256_sign
#define include_p256_sign 1
#endif

#ifndef include_p256_keygen
#define include_p256_keygen 1
#endif

#ifndef include_p256_ecdh
#define include_p256_ecdh 1
#endif

#ifndef include_p256_raw_scalarmult_generic
#define include_p256_raw_scalarmult_generic 1
#endif

#ifndef include_p256_raw_scalarmult_base
#define include_p256_raw_scalarmult_base 1
#endif

#ifndef include_p256_to_octet_string_uncompressed
#define include_p256_to_octet_string_uncompressed 1
#endif

#ifndef include_p256_to_octet_string_compressed
#define include_p256_to_octet_string_compressed 1
#endif

#ifndef include_p256_to_octet_string_hybrid
#define include_p256_to_octet_string_hybrid 1
#endif

#ifndef include_p256_decompress_point
#define include_p256_decompress_point 1
#endif

#ifndef include_p256_decode_point
#define include_p256_decode_point 1
#endif


// Target settings

/**
 * Enables the use of FPU instructions (vmov, vldm).
 * This will only work if the CPU has an FPU, such as Cortex-M4F.
 * It will not work on Cortex-M4 (without FPU).
 * If enabled, the code will run faster.
 * The default is to use the __ARM_FP macro that the compiler defines.
 */
#ifndef has_fpu
#ifdef __ARM_FP
#define has_fpu 1
#else
#define has_fpu 0
#endif
#endif

/**
 * If 0, the implementation conditionally loads data from different RAM locations depending
 * on secret data, so 0 should not be used on CPUs that have data cache, such as Cortex-A53.
 *
 * 0 is suited for embedded devices running CPUs like Cortex-M4 and Cortex-M33, which don't
 * have any data cache.
 *
 * 1 is suited for Cortex-A processors.
 */
#ifndef has_d_cache
#define has_d_cache 0
#endif

// Optimization settings

/**
 * If enabled, keygen and sign uses a specialized scalar multiplication routine when multiplying by
 * the base point, which dramatically improves performance, at the expense of using more code space.
 * If disabled, keygen and sign will use the generic variable base scalar multiplication routine.
 */
#ifndef use_fast_p256_basemult
#define use_fast_p256_basemult 1
#endif

/**
 * Enable this to save some code space, at expense of performance.
 * When disabled, a specialized field squaring routine will be used rather
 * than re-using the multiplication routine.
 */
#ifndef use_mul_for_sqr
#define use_mul_for_sqr 0
#endif

// Derived settings (do not modify)
#define include_p256_basemult (include_p256_keygen || include_p256_sign || include_p256_raw_scalarmult_base)
#define include_fast_p256_basemult (use_fast_p256_basemult && include_p256_basemult)
#define include_p256_varmult (include_p256_ecdh || include_p256_raw_scalarmult_generic)
#define include_p256_mult (include_p256_verify || include_p256_basemult || include_p256_varmult)

#endif
