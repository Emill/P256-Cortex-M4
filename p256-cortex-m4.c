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

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "p256-cortex-m4-config.h"
#include "p256-cortex-m4.h"

typedef const uint32_t (*constarr)[8];

struct FGInteger {
    // To get the value this struct represents,
    // interpret signed_value as a two's complement 288-bit little endian integer,
    // and negate if flip_sign is -1
    int flip_sign; // 0 or -1
    uint32_t signed_value[9]; // of 288 bits, 257 are useful (top 31 bits are sign-extended from bit 256)
};

struct XYInteger {
    // To get the value this struct represents,
    // interpret signed_value as an unsigned 288-bit little endian integer,
    // and negate if flip_sign is -1
    int flip_sign; // 0 or -1
    uint32_t value[8]; // unsigned value, 0 <= value < P256_order
};

int divsteps2_31(int delta, uint32_t f, uint32_t g, uint32_t res_matrix[4]);
void matrix_mul_fg_9(uint32_t a, uint32_t b, const struct FGInteger fg[2], struct FGInteger *res);
void matrix_mul_p256_order(uint32_t a, uint32_t b, const struct XYInteger xy[2], struct XYInteger *res);

void P256_to_montgomery(uint32_t aR[8], const uint32_t a[8]);
void P256_from_montgomery(uint32_t a[8], const uint32_t aR[8]);
bool P256_check_range_p(const uint32_t a[8]);

bool P256_check_range_n(const uint32_t a[8]);
void P256_mul_mod_n(uint32_t res[8], const uint32_t a[8], const uint32_t b[8]);
void P256_add_mod_n(uint32_t res[8], const uint32_t a[8], const uint32_t b[8]);
void P256_mod_n_inv_vartime(uint32_t res[8], const uint32_t a[8]);
void P256_reduce_mod_n_32bytes(uint32_t res[8], const uint32_t a[8]);

void ecc_select_point(uint32_t (*output)[8], uint32_t* table, uint32_t num_coordinates, uint32_t index);

void P256_jacobian_to_affine(uint32_t affine_mont_x[8], uint32_t affine_mont_y[8], const uint32_t jacobian_mont[3][8]);
bool P256_point_is_on_curve(const uint32_t x_mont[8], const uint32_t y_mont[8]);
bool P256_decompress_point(uint32_t y[8], const uint32_t x[8], uint32_t y_parity);
void P256_double_j(uint32_t jacobian_point_out[3][8], const uint32_t jacobian_point_in[3][8]);
void P256_add_sub_j(uint32_t jacobian_point1[3][8], const uint32_t (*point2)[8], bool is_sub, bool p2_is_affine);
bool P256_verify_last_step(const uint32_t r[8], const uint32_t jacobian_point[3][8]);

void P256_negate_mod_p_if(uint32_t out[8], const uint32_t in[8], uint32_t should_negate);
void P256_negate_mod_n_if(uint32_t out[8], const uint32_t in[8], uint32_t should_negate);

extern uint32_t P256_order[9];

#if include_p256_mult
static const uint32_t one_montgomery[8] = {1, 0, 0, 0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0};
#endif

#if include_p256_verify
// This table contains 1G, 3G, 5G, ... 15G in affine coordinates in montgomery form
static const uint32_t p256_basepoint_precomp[8][2][8] = {
{{0x18a9143c, 0x79e730d4, 0x5fedb601, 0x75ba95fc, 0x77622510, 0x79fb732b, 0xa53755c6, 0x18905f76},
{0xce95560a, 0xddf25357, 0xba19e45c, 0x8b4ab8e4, 0xdd21f325, 0xd2e88688, 0x25885d85, 0x8571ff18}},
{{0x4eebc127, 0xffac3f90, 0x87d81fb, 0xb027f84a, 0x87cbbc98, 0x66ad77dd, 0xb6ff747e, 0x26936a3f},
{0xc983a7eb, 0xb04c5c1f, 0x861fe1a, 0x583e47ad, 0x1a2ee98e, 0x78820831, 0xe587cc07, 0xd5f06a29}},
{{0xc45c61f5, 0xbe1b8aae, 0x94b9537d, 0x90ec649a, 0xd076c20c, 0x941cb5aa, 0x890523c8, 0xc9079605},
{0xe7ba4f10, 0xeb309b4a, 0xe5eb882b, 0x73c568ef, 0x7e7a1f68, 0x3540a987, 0x2dd1e916, 0x73a076bb}},
{{0xa0173b4f, 0x746354e, 0xd23c00f7, 0x2bd20213, 0xc23bb08, 0xf43eaab5, 0xc3123e03, 0x13ba5119},
{0x3f5b9d4d, 0x2847d030, 0x5da67bdd, 0x6742f2f2, 0x77c94195, 0xef933bdc, 0x6e240867, 0xeaedd915}},
{{0x264e20e8, 0x75c96e8f, 0x59a7a841, 0xabe6bfed, 0x44c8eb00, 0x2cc09c04, 0xf0c4e16b, 0xe05b3080},
{0xa45f3314, 0x1eb7777a, 0xce5d45e3, 0x56af7bed, 0x88b12f1a, 0x2b6e019a, 0xfd835f9b, 0x86659cd}},
{{0x6245e404, 0xea7d260a, 0x6e7fdfe0, 0x9de40795, 0x8dac1ab5, 0x1ff3a415, 0x649c9073, 0x3e7090f1},
{0x2b944e88, 0x1a768561, 0xe57f61c8, 0x250f939e, 0x1ead643d, 0xc0daa89, 0xe125b88e, 0x68930023}},
{{0x4b2ed709, 0xccc42563, 0x856fd30d, 0xe356769, 0x559e9811, 0xbcbcd43f, 0x5395b759, 0x738477ac},
{0xc00ee17f, 0x35752b90, 0x742ed2e3, 0x68748390, 0xbd1f5bc1, 0x7cd06422, 0xc9e7b797, 0xfbc08769}},
{{0xbc60055b, 0x72bcd8b7, 0x56e27e4b, 0x3cc23ee, 0xe4819370, 0xee337424, 0xad3da09, 0xe2aa0e43},
{0x6383c45d, 0x40b8524f, 0x42a41b25, 0xd7663554, 0x778a4797, 0x64efa6de, 0x7079adf4, 0x2042170a}}
};
#endif

#if include_fast_p256_basemult
// This contains two tables, 8 points each in affine coordinates in montgomery form
// The first table contains these points:
// (2^192 - 2^128 - 2^64 - 1)G
// (2^192 - 2^128 - 2^64 + 1)G
// (2^192 - 2^128 + 2^64 - 1)G
// (2^192 - 2^128 + 2^64 + 1)G
// (2^192 + 2^128 - 2^64 - 1)G
// (2^192 + 2^128 - 2^64 + 1)G
// (2^192 + 2^128 + 2^64 - 1)G
// (2^192 + 2^128 + 2^64 + 1)G
// The second table contains the same points multiplied by 2^32
static const uint32_t p256_basepoint_precomp2[2][8][2][8] =
{
{
{{0x670844e0, 0x52d8a7c9, 0xef68a29d, 0xe33bdc, 0x4bdb7361, 0xf3d2848, 0x91c5304d, 0x5222c821},
{0xdf73fc25, 0xea6d2944, 0x255c81b, 0xa04c0f55, 0xefe488a8, 0x29acdc97, 0x80a560de, 0xbe2e158f}},
{{0x2b13e673, 0xfc8511ee, 0xd103ed24, 0xffc58dee, 0xea7e99b8, 0x1022523a, 0x4afc8a17, 0x8f43ea39},
{0xc5f33d0b, 0x8f4e2dbc, 0xd0aa1681, 0x3bc099fa, 0x79ff9df1, 0xffbb7b41, 0xd58b57c4, 0x180de09d}},
{{0x8bd1cda5, 0x56430752, 0x8e05eda5, 0x1807577f, 0x956896e9, 0x99c699b, 0xf1f0efb5, 0x83d6093d},
{0xed97061c, 0xef5af17e, 0x30d4c3c, 0x35b977b8, 0x49229439, 0x81fa75a2, 0xa0b6d35d, 0xf5a22070}},
{{0x74f81cf1, 0x814c5365, 0x120065b, 0xe30baff7, 0x15132621, 0x80ae1256, 0x36a80788, 0x16d2b8cb},
{0xecc50bca, 0x33d14697, 0x17aedd21, 0x19a9dfb0, 0xedc3f766, 0x523fbcc7, 0xb2cf5afd, 0x9c4de6dd}},
{{0xcf0d9f6d, 0x5305a9e6, 0x81a9b021, 0x5839172f, 0x75c687cf, 0xcca7a4dd, 0x844be22f, 0x36d59b3e},
{0x111a53e9, 0xcace7e62, 0xf063f3a1, 0x91c843d4, 0xda812da, 0xbf77e5f0, 0x437f3176, 0xe64af9c}},
{{0xcf07517d, 0xdbd568bb, 0xba6830b9, 0x2f1afba2, 0xe6c4c2a6, 0x15b6807c, 0xe4966aef, 0x91c7eabc},
{0xd6b2b6e6, 0x716dea1b, 0x19f85b4b, 0x248c43d1, 0x4a315e2a, 0x16dcfd60, 0xc72b3d0b, 0x15fdd303}},
{{0x42b7dfd5, 0xe40bf9f4, 0x2d934f2a, 0x673689f3, 0x30a6f50b, 0x8314beb4, 0x976ec64e, 0xd17af2bc},
{0x1ee7ddf1, 0x39f66c4f, 0x68ea373c, 0x7f68e18b, 0x53d0b186, 0x5166c1f2, 0x7be58f14, 0x95dda601}},
{{0x42913074, 0xd5ae356, 0x48a542b1, 0x55491b27, 0xb310732a, 0x469ca665, 0x5f1a4cc1, 0x29591d52},
{0xb84f983f, 0xe76f5b6b, 0x9f5f84e1, 0xbe7eef41, 0x80baa189, 0x1200d496, 0x18ef332c, 0x6376551f}}
},
{
{{0x7c4e54f5, 0xb9e5cbc0, 0xe1410e34, 0xc53a1a17, 0xec454425, 0x3e199130, 0x1700902e, 0xb029c97e},
{0x786423b6, 0x2de66e11, 0xb41a95be, 0x262dc914, 0x451b683, 0x51766abd, 0x85bb6fb1, 0x55ad5f34}},
{{0x9066cb79, 0x74f4f1c, 0x30c8b94e, 0x1ab31bd6, 0xd74275b3, 0x6d3f012f, 0x9ddcce40, 0xa214d0b1},
{0xd165050a, 0x24aedf74, 0xe0e5dc3e, 0x95f17ece, 0xd9224456, 0x6ada9cda, 0x2dd60eea, 0x1fadb2d1}},
{{0xe20cfb9b, 0xa3d83091, 0xba76e0cb, 0xae79c975, 0xc8858a6e, 0xa5f2a588, 0x874a3168, 0xe897a5f4},
{0x7d48f096, 0xf6c1ef40, 0xc35b132c, 0x1f9c516b, 0x53c479fd, 0xe1040f91, 0x9df06743, 0x60e881f}},
{{0x52a90e51, 0x9e0ad72, 0x38c50a96, 0xb7e66ea3, 0x7d997770, 0xab32ad05, 0x445671cb, 0xceaffe2},
{0x5d37cc99, 0xdfbe753c, 0xe0fea2d5, 0x95d068cc, 0x4dd77cb6, 0x1e37cdda, 0x55530688, 0x88c5a4bb}},
{{0xc7744f1, 0x3413f033, 0xbc816702, 0x23c05c89, 0x1192b5ac, 0x2322ee9a, 0x373180bb, 0xc1636a0},
{0xbdde0207, 0xfe2f3d4, 0xc23578d8, 0xe1a093a, 0xc888ead, 0x6e5f0d1, 0x52a2b660, 0x9ca285a5}},
{{0xce923964, 0xdae76995, 0xa34c7993, 0xcc96493a, 0xea73d9e7, 0xd19b5144, 0x311e6e34, 0x4a5c263},
{0xd9a2a443, 0x7db5b32b, 0x2cfd960c, 0x3754bd33, 0xa430f15, 0xc5bcc98, 0xd9a94574, 0x5651201f}},
{{0xfc0418fe, 0xebdd8921, 0x34e20036, 0x37015b39, 0xdf03a353, 0xcf4fcd8f, 0xf12cab16, 0xdc2de6e1},
{0xd071df14, 0x9c17cc1a, 0x63415530, 0xd7c5e6a3, 0x68f3fb1e, 0xb5301660, 0x18269301, 0xb5f70bc9}},
{{0x79ec1a0f, 0x2d8daefd, 0xceb39c97, 0x3bbcd6fd, 0x58f61a95, 0xf5575ffc, 0xadf7b420, 0xdbd986c4},
{0x15f39eb7, 0x81aa8814, 0xb98d976c, 0x6ee2fcf5, 0xcf2f717d, 0x5465475d, 0x6860bbd0, 0x8e24d3c4}}
}
};
#endif

#if include_p256_verify || include_p256_sign
// Takes the leftmost 256 bits in hash (treated as big endian),
// and converts to little endian integer z.
static void hash_to_z(uint32_t z[8], const uint8_t* hash, uint32_t hashlen) {
    if (hashlen > 32) {
        hashlen = 32;
    }
    for (uint32_t i = 0; i < hashlen; i++) {
        ((uint8_t*)z)[i] = hash[hashlen - 1 - i];
    }
    for (uint32_t i = hashlen; i < 32; i++) {
        ((uint8_t*)z)[i] = 0;
    }
}
#endif

#if include_p256_verify
// Creates a representation of a (little endian integer),
// so that r[0] + 2*r[1] + 2^2*r[2] + 2^3*r[3] + ... = a,
// where each r[i] is -15, -13, ..., 11, 13, 15 or 0.
// Only around 1/5.5 of the r[i] will be non-zero.
static void slide_257(signed char r[257], const uint8_t a[32]) {
    for (int i = 0; i < 256; ++i) {
        r[i] = 1 & (a[i >> 3] >> (i & 7));
    }
    r[256] = 0;

    for (int i = 0; i < 256; i++) {
        if (r[i] != 0) {
            for (int b = 1; b <= 4 && i + b < 256; b++) {
                if (r[i + b] != 0) {
                    if (r[i] + (r[i + b] << b) <= 15) {
                        r[i] += r[i + b] << b; r[i + b] = 0;
                    } else if (r[i] - (r[i + b] << b) >= -15) {
                        r[i] -= r[i + b] << b;
                        for (;;) {
                            r[i + b] = 0;
                            b++;
                            if (!r[i + b]) {
                                r[i + b] = 1;
                                b--; // Will be added back after loop footer b++
                                break;
                            }
                        }
                    } else {
                        break;
                    }
                }
            }
        }
    }
}
#endif

#if include_p256_sign
void P256_mod_n_inv(uint32_t out[8], const uint32_t in[8]) {
    // This function follows the algorithm in section 12.1 of https://gcd.cr.yp.to/safegcd-20190413.pdf.
    // It has been altered in the following ways:
    //   1. Due to 32-bit cpu, we use 24 * 31 iterations instead of 12 * 62.
    //   2. P-256 modulus instead of 2^255-19.
    //      744 iterations are still enough and slightly more than the required 741 (floor((49*256+57)/17)).
    //   3. Step 5 has been corrected to go back to step 2 instead of step 3.
    //   4. The order of the matrix multiplications in step 6 has been changed to (T24*(T23*(T22*(...*(T1*[0, 1]))))),
    //      where [0, 1] is a column vector to make it possible to be able to extract the "top-right corner", v, of T24*T23*...*T1.
    //      The result v will then be contained in the first element of the resulting column vector.
    
    struct {
        struct FGInteger fg[2]; // f and g
        struct XYInteger xy[2]; // x and y
    } state[2]; // "current" and "next"
    
    state[0].fg[0].flip_sign = 0; // non-negative f
    memcpy(&state[0].fg[0].signed_value, P256_order, 36); // f
    state[0].fg[1].flip_sign = 0; // non-negative g
    memcpy(&state[0].fg[1].signed_value, in, 32); // g
    state[0].fg[1].signed_value[8] = 0; // upper bits of g are 0
    memset(&state[0].xy, 0, sizeof(state[0].xy));
    // We later need a factor 2^-744. The montgomery multiplication gives 2^(24*-32)=2^-768, so multiply the init value (1) by 2^24 here.
    state[0].xy[1].value[0] = 1U << 24;
    
    int delta = 1;
    for (int i = 0; i < 24; i++) {
        // Scaled translation matrix Ti
        uint32_t matrix[4]; // element range: [-2^30, 2^31] (negative numbers are stored in two's complement form)
        
        // Decode f and g into two's complement representation and use the lowest 32 bits in the divsteps2_31 calculation
        uint32_t negate_f = state[i % 2].fg[0].flip_sign;
        uint32_t negate_g = state[i % 2].fg[1].flip_sign;
        delta = divsteps2_31(delta, (state[i % 2].fg[0].signed_value[0] ^ negate_f) - negate_f, (state[i % 2].fg[1].signed_value[0] ^ negate_g) - negate_g, matrix);
        
        // "Jump step", calculates the new f and g values that applies after 31 divstep2 iterations
        matrix_mul_fg_9(matrix[0], matrix[1], state[i % 2].fg, &state[(i + 1) % 2].fg[0]);
        matrix_mul_fg_9(matrix[2], matrix[3], state[i % 2].fg, &state[(i + 1) % 2].fg[1]);
        
        // Iterate the result vector
        // Due to montgomery multiplication inside this function, each step also adds a 2^-32 factor
        matrix_mul_p256_order(matrix[0], matrix[1], state[i % 2].xy, &state[(i + 1) % 2].xy[0]);
        matrix_mul_p256_order(matrix[2], matrix[3], state[i % 2].xy, &state[(i + 1) % 2].xy[1]);
    }
    // Calculates val^-1 = sgn(f) * v * 2^-744, where v is the "top-right corner" of the resulting T24*T23*...*T1 matrix.
    // In this implementation, at this point x contains v * 2^-744.
    P256_negate_mod_n_if(out, &state[0].xy[0].value[0], (state[0].xy[0].flip_sign ^ state[0].fg[0].flip_sign ^ state[0].fg[0].signed_value[8]) & 1);
}
#endif

#if include_p256_varmult || (include_p256_basemult && !use_fast_p256_basemult)
// Constant time abs
static inline uint32_t abs_int(int8_t a) {
    uint32_t a_u = (uint32_t)(int32_t)a;
    uint32_t mask = a_u >> 31;
    mask |= mask << 1;
    mask |= mask << 2;
    uint32_t result = (-a) & mask;
    result |= a & (mask ^ 0xf);
    return result;
}

// Calculates scalar*P in constant time (except for the scalars 2 and n-2, for which the results take a few extra cycles to compute)
static void scalarmult_variable_base(uint32_t output_mont_x[8], uint32_t output_mont_y[8], const uint32_t input_mont_x[8], const uint32_t input_mont_y[8], const uint32_t scalar[8]) {
    // Based on https://eprint.iacr.org/2014/130.pdf, Algorithm 1.
    
    uint32_t scalar2[8];
    int8_t e[64];
    
    // The algorithm used requires the scalar to be odd. If even, negate the scalar modulo p to make it odd, and later negate the end result.
    bool even = (scalar[0] & 1) ^ 1;
    P256_negate_mod_n_if(scalar2, scalar, even);
    
    // Rewrite the scalar as e[0] + 2^4*e[1] + 2^8*e[2] + ... + 2^252*e[63], where each e[i] is an odd number and -15 <= e[i] <= 15.
    e[0] = scalar2[0] & 0xf;
    for (int i = 1; i < 64; i++) {
        // Extract 4 bits
        e[i] = (scalar2[i / 8] >> ((i % 8) * 4)) & 0xf;
        // If even, subtract 2^4 from e[i - 1] and add 1 to e[i]
        e[i - 1] -= ((e[i] & 1) ^ 1) << 4;
        e[i] |= 1;
    }
    
    // Create a table of P, 3P, 5P, ... 15P.
    uint32_t table[8][3][8];
    memcpy(table[0][0], input_mont_x, 32);
    memcpy(table[0][1], input_mont_y, 32);
    memcpy(table[0][2], one_montgomery, 32);
    P256_double_j(table[7], (constarr)table[0]);
    for (int i = 1; i < 8; i++) {
        memcpy(table[i], table[7], 96);
        P256_add_sub_j(table[i], (constarr)table[i - 1], 0, 0);
    }
    
    // Calculate the result as (((((((((e[63]*G)*2^4)+e[62])*2^4)+e[61])*2^4)...)+e[1])*2^4)+e[0] = (2^252*e[63] + 2^248*e[62] + ... + e[0])*G.
    
    uint32_t current_point[3][8];
    
    // e[63] is never negative
    #if has_d_cache
    ecc_select_point(current_point, (uint32_t*)table, 3, e[63] >> 1);
    #else
    memcpy(current_point, table[e[63] >> 1], 96);
    #endif
    
    for (uint32_t i = 63; i --> 0;) {
        for (int j = 3; j >= 0; j--) {
            P256_double_j(current_point, (constarr)current_point);
        }
        uint32_t selected_point[3][8];
        #if has_d_cache
        ecc_select_point(selected_point, (uint32_t*)table, 3, abs_int(e[i]) >> 1);
        #else
        memcpy(selected_point, table[abs_int(e[i]) >> 1], 96);
        #endif
        P256_negate_mod_p_if(selected_point[1], selected_point[1], (uint8_t)e[i] >> 7);
        
        // There is (only) one odd input scalar that leads to an exception when i == 0: n-2,
        // in that case current_point will be equal to selected_point and hence a doubling
        // will occur instead. We don't bother fixing the same constant time for that case since
        // the probability of that random value to be generated is around 1/2^255 and an
        // attacker could easily test this case anyway.
        P256_add_sub_j(current_point, (constarr)selected_point, false, false);
    }
    P256_jacobian_to_affine(output_mont_x, output_mont_y, (constarr)current_point);
    
    // If the scalar was initially even, we now negate the result to get the correct result, since -(scalar*G) = (-scalar*G).
    // This is done by negating y, since -(x,y) = (x,-y).
    P256_negate_mod_p_if(output_mont_y, output_mont_y, even);
}
#endif

#define get_bit(arr, i) ((arr[(i) / 32] >> ((i) % 32)) & 1)

#if include_p256_basemult
#if include_fast_p256_basemult
// Calculates scalar*G in constant time
static void scalarmult_fixed_base(uint32_t output_mont_x[8], uint32_t output_mont_y[8], const uint32_t scalar[8]) {
    uint32_t scalar2[8];
    
    // Just as with the algorithm used in variable base scalar multiplication, this algorithm requires the scalar to be odd.
    bool even = (scalar[0] & 1) ^ 1;
    P256_negate_mod_n_if(scalar2, scalar, even);
    
    // This algorithm conceptually rewrites the odd scalar as s[0] + 2^1*s[1] + 2^2*s[2] + ... + 2^255*s[255], where each s[i] is -1 or 1.
    // By initially setting s[i] to the corresponding bit S[i] in the original odd scalar S, we go from lsb to msb, and whenever a value s[i] is 0,
    // increase s[i] by 1 and decrease s[i-1] by 2.
    // This will result in that s[i] = S[i+1] == 1 ? 1 : -1 for i < 255, and s[255] = 1.
    
    // We then form the scalars abs(s[j] + s[j+64]*2^64 + s[j+128]*2^128 + s[j+192]*2^192)*(2^32 * floor(j / 32)) for different 0 <= j < 64.
    // Each scalar times G has already been precomputed in p256_basepoint_precomp2.
    // That way we only need 31 point doublings and 63 point additions.
    
    uint32_t current_point[3][8];
    uint32_t selected_point[2][8];
    
    #if !has_d_cache
    // Load table into RAM, for example if the the table lies on external memory mapped flash, which can easily be intercepted.
    uint32_t precomp[2][8][2][8];
    memcpy(precomp, p256_basepoint_precomp2, sizeof(p256_basepoint_precomp2));
    #endif
    
    for (uint32_t i = 32; i --> 0;) {
        {
            uint32_t mask = get_bit(scalar2, i + 32 + 1) | (get_bit(scalar2, i + 64 + 32 + 1) << 1) | (get_bit(scalar2, i + 2 * 64 + 32 + 1) << 2);
            if (i == 31) {
                #if has_d_cache
                ecc_select_point(current_point, (uint32_t*)p256_basepoint_precomp2[1], 2, mask);
                #else
                memcpy(current_point, precomp[1][mask], 64);
                #endif
                memcpy(current_point[2], one_montgomery, 32);
            } else {
                P256_double_j(current_point, (constarr)current_point);
                
                uint32_t sign = get_bit(scalar2, i + 3 * 64 + 32 + 1) - 1; // positive: 0, negative: -1
                mask = (mask ^ sign) & 7;
                #if has_d_cache
                ecc_select_point(selected_point, (uint32_t*)p256_basepoint_precomp2[1], 2, mask);
                #else
                memcpy(selected_point, precomp[1][mask], 64);
                #endif
                P256_negate_mod_p_if(selected_point[1], selected_point[1], sign & 1);
                P256_add_sub_j(current_point, (constarr)selected_point, false, true);
            }
        }
        {
            uint32_t mask = get_bit(scalar2, i + 1) | (get_bit(scalar2, i + 64 + 1) << 1) | (get_bit(scalar2, i + 2 * 64 + 1) << 2);
            uint32_t sign = get_bit(scalar2, i + 3 * 64 + 1) - 1; // positive: 0, negative: -1
            mask = (mask ^ sign) & 7;
            #if has_d_cache
            ecc_select_point(selected_point, (uint32_t*)p256_basepoint_precomp2[0], 2, mask);
            #else
            memcpy(selected_point, precomp[0][mask], 64);
            #endif
            P256_negate_mod_p_if(selected_point[1], selected_point[1], sign & 1);
            P256_add_sub_j(current_point, (constarr)selected_point, false, true);
        }
    }
    P256_jacobian_to_affine(output_mont_x, output_mont_y, (constarr)current_point);
    
    // Negate final result if the scalar was initially even.
    P256_negate_mod_p_if(output_mont_y, output_mont_y, even);
}
#else
static void scalarmult_fixed_base(uint32_t output_mont_x[8], uint32_t output_mont_y[8], const uint32_t scalar[8]) {
    #if !include_p256_verify
    static const uint32_t p[2][8] =
    {{0x18a9143c, 0x79e730d4, 0x5fedb601, 0x75ba95fc, 0x77622510, 0x79fb732b, 0xa53755c6, 0x18905f76},
    {0xce95560a, 0xddf25357, 0xba19e45c, 0x8b4ab8e4, 0xdd21f325, 0xd2e88688, 0x25885d85, 0x8571ff18}};
    scalarmult_variable_base(output_mont_x, output_mont_y, p[0], p[1], scalar);
    #else
    scalarmult_variable_base(output_mont_x, output_mont_y, p256_basepoint_precomp[0][0], p256_basepoint_precomp[0][1], scalar);
    #endif
}
#endif
#endif

void p256_convert_endianness(void* output, const void* input, size_t byte_len) {
    for (size_t i = 0; i < byte_len / 2; i++) {
        uint8_t t = ((uint8_t*)input)[byte_len - 1 - i];
        ((uint8_t*)output)[byte_len - 1 - i] = ((uint8_t*)input)[i];
        ((uint8_t*)output)[i] = t;
    }
}

#if include_p256_verify
bool p256_verify(const uint32_t public_key_x[8], const uint32_t public_key_y[8], const uint8_t* hash, uint32_t hashlen_in_bytes, const uint32_t r[8], const uint32_t s[8]) {
    if (!P256_check_range_n(r) || !P256_check_range_n(s)) {
        return false;
    }
    
    if (!P256_check_range_p(public_key_x) || !P256_check_range_p(public_key_y)) {
        return false;
    }
    
    uint32_t pk_table[8][3][8];
    P256_to_montgomery(pk_table[0][0], public_key_x);
    P256_to_montgomery(pk_table[0][1], public_key_y);
    memcpy(pk_table[0][2], one_montgomery, 32);
    
    if (!P256_point_is_on_curve(pk_table[0][0], pk_table[0][1])) {
        return false;
    }
    
    // Create a table of P, 3P, 5P, ..., 15P, where P is the public key.
    P256_double_j(pk_table[7], (constarr)pk_table[0]);
    for (int i = 1; i < 8; i++) {
        memcpy(pk_table[i], pk_table[7], 96);
        P256_add_sub_j(pk_table[i], (constarr)pk_table[i - 1], 0, 0);
    }
    
    uint32_t z[8], w[8], u1[8], u2[8];
    
    hash_to_z(z, hash, hashlen_in_bytes);
    
    #if include_p256_sign
    P256_mod_n_inv(w, s);
    #else
    // Use smaller implementation if we don't need constant time version
    P256_mod_n_inv_vartime(w, s);
    #endif
    
    P256_mul_mod_n(u1, z, w);
    P256_mul_mod_n(u2, r, w);
    
    // Each value in these arrays will be an odd integer v, so that -15 <= v <= 15.
    // Around 1/5.5 of them will be non-zero.
    signed char slide_bp[257], slide_pk[257];
    slide_257(slide_bp, (uint8_t*)u1);
    slide_257(slide_pk, (uint8_t*)u2);
    
    uint32_t cp[3][8] = {0};
    
    for (int i = 256; i >= 0; i--) {
        P256_double_j(cp, (constarr)cp);
        if (slide_bp[i] > 0) {
            P256_add_sub_j(cp, p256_basepoint_precomp[slide_bp[i]/2], 0, 1);
        } else if (slide_bp[i] < 0) {
            P256_add_sub_j(cp, p256_basepoint_precomp[(-slide_bp[i])/2], 1, 1);
        }
        if (slide_pk[i] > 0) {
            P256_add_sub_j(cp, (constarr)pk_table[slide_pk[i]/2], 0, 0);
        } else if (slide_pk[i] < 0) {
            P256_add_sub_j(cp, (constarr)pk_table[(-slide_pk[i])/2], 1, 0);
        }
    }
    
    return P256_verify_last_step(r, (constarr)cp);
}
#endif

#if include_p256_sign
bool p256_sign_step1(struct SignPrecomp *result, const uint32_t k[8]) {
    do {
        uint32_t point_res[2][8];
        if (!P256_check_range_n(k)) {
            break;
        }
        scalarmult_fixed_base(point_res[0], point_res[1], k);
        P256_mod_n_inv(result->k_inv, k);
        P256_from_montgomery(result->r, point_res[0]);
        P256_reduce_mod_n_32bytes(result->r, result->r);
        
        uint32_t r_sum = 0;
        for (int i = 0; i < 8; i++) {
            r_sum |= result->r[i];
        }
        if (r_sum == 0) {
            break;
        }
        return true;
    } while (false);
    
    memset(result, 0, sizeof(struct SignPrecomp));
    return false;
}

bool p256_sign_step2(uint32_t r[8], uint32_t s[8], const uint8_t* hash, uint32_t hashlen_in_bytes, const uint32_t private_key[8], struct SignPrecomp *sign_precomp) {
    do {
        if (!P256_check_range_n(sign_precomp->k_inv) || !P256_check_range_n(sign_precomp->r)) { // just make sure user did not input an obviously invalid precomp
            break;
        }
        uint32_t *const z = r;
        hash_to_z(z, hash, hashlen_in_bytes);
        P256_mul_mod_n(s, sign_precomp->r, private_key);
        P256_add_mod_n(s, z, s);
        P256_mul_mod_n(s, sign_precomp->k_inv, s);
        
        memcpy(r, sign_precomp->r, 32);
        
        uint32_t s_sum = 0;
        for (int i = 0; i < 8; i++) {
            s_sum |= s[i];
        }
        if (s_sum == 0) {
            break;
        }
        memset(sign_precomp, 0, sizeof(*sign_precomp));
        return true;
    } while (false);
    
    memset(r, 0, 32);
    memset(s, 0, 32);
    return false;
}

bool p256_sign(uint32_t r[8], uint32_t s[8], const uint8_t* hash, uint32_t hashlen_in_bytes, const uint32_t private_key[8], const uint32_t k[8]) {
    struct SignPrecomp t;
    if (!p256_sign_step1(&t, k)) {
        memset(r, 0, 32);
        memset(s, 0, 32);
        return false;
    }
    return p256_sign_step2(r, s, hash, hashlen_in_bytes, private_key, &t);
}
#endif

#if include_p256_keygen || include_p256_raw_scalarmult_base
bool p256_scalarmult_base(uint32_t result_x[8], uint32_t result_y[8], const uint32_t scalar[8]) {
    if (!P256_check_range_n(scalar)) {
        return false;
    }
    scalarmult_fixed_base(result_x, result_y, scalar);
    P256_from_montgomery(result_x, result_x);
    P256_from_montgomery(result_y, result_y);
    return true;
    
}

#if include_p256_keygen
bool p256_keygen(uint32_t public_key_x[8], uint32_t public_key_y[8], const uint32_t private_key[8]) {
    return p256_scalarmult_base(public_key_x, public_key_y, private_key);
}
#endif
#endif


#if include_p256_varmult
static bool p256_scalarmult_generic_no_scalar_check(uint32_t output_mont_x[8], uint32_t output_mont_y[8], const uint32_t scalar[8], const uint32_t in_x[8], const uint32_t in_y[8]) {
    if (!P256_check_range_p(in_x) || !P256_check_range_p(in_y)) {
        return false;
    }
    
    P256_to_montgomery(output_mont_x, in_x);
    P256_to_montgomery(output_mont_y, in_y);
    
    if (!P256_point_is_on_curve(output_mont_x, output_mont_y)) {
        return false;
    }
    
    scalarmult_variable_base(output_mont_x, output_mont_y, output_mont_x, output_mont_y, scalar);
    return true;
}

#if include_p256_raw_scalarmult_generic
bool p256_scalarmult_generic(uint32_t result_x[8], uint32_t result_y[8], const uint32_t scalar[8], const uint32_t in_x[8], const uint32_t in_y[8]) {
    if (!P256_check_range_n(scalar) || !p256_scalarmult_generic_no_scalar_check(result_x, result_y, scalar, in_x, in_y)) {
        return false;
    }
    P256_from_montgomery(result_x, result_x);
    P256_from_montgomery(result_y, result_y);
    return true;
}
#endif

#if include_p256_ecdh
bool p256_ecdh_calc_shared_secret(uint8_t shared_secret[32], const uint32_t private_key[8], const uint32_t others_public_key_x[8], const uint32_t others_public_key_y[8]) {
    uint32_t result_x[8], result_y[8];
    if (!p256_scalarmult_generic_no_scalar_check(result_x, result_y, private_key, others_public_key_x, others_public_key_y)) {
        return false;
    }
    P256_from_montgomery(result_x, result_x);
    p256_convert_endianness(shared_secret, result_x, 32);
    return true;
}
#endif
#endif

#if include_p256_to_octet_string_uncompressed
void p256_point_to_octet_string_uncompressed(uint8_t out[65], const uint32_t x[8], const uint32_t y[8]) {
    out[0] = 4;
    p256_convert_endianness(out + 1, x, 32);
    p256_convert_endianness(out + 33, y, 32);
}
#endif

#if include_p256_to_octet_string_compressed
void p256_point_to_octet_string_compressed(uint8_t out[33], const uint32_t x[8], const uint32_t y[8]) {
    out[0] = 2 + (y[0] & 1);
    p256_convert_endianness(out + 1, x, 32);
}
#endif

#if include_p256_to_octet_string_hybrid
void p256_point_to_octet_string_hybrid(uint8_t out[65], const uint32_t x[8], const uint32_t y[8]) {
    out[0] = 6 + (y[0] & 1);
    p256_convert_endianness(out + 1, x, 32);
    p256_convert_endianness(out + 33, y, 32);
}
#endif

#if include_p256_decode_point || include_p256_decompress_point
bool p256_octet_string_to_point(uint32_t x[8], uint32_t y[8], const uint8_t* input, uint32_t input_len_in_bytes) {
    if (input_len_in_bytes < 33) return false;
    p256_convert_endianness(x, input + 1, 32);
    if (!P256_check_range_p(x)) {
        return false;
    }
    #if include_p256_decode_point
    if ((input[0] == 4 || (input[0] >> 1) == 3) && input_len_in_bytes == 65) {
        p256_convert_endianness(y, input + 33, 32);
        if (!P256_check_range_p(y)) {
            return false;
        }
        if ((input[0] >> 1) == 3 && (input[0] & 1) != (y[0] & 1)) {
            return false;
        }
        uint32_t x_mont[8], y_mont[8];
        P256_to_montgomery(x_mont, x);
        P256_to_montgomery(y_mont, y);
        return P256_point_is_on_curve(x_mont, y_mont);
    }
    #endif
    #if include_p256_decompress_point
    if ((input[0] >> 1) == 1 && input_len_in_bytes == 33) {
        return P256_decompress_point(y, x, input[0] & 1);
    }
    #endif
    return false;
}
#endif
