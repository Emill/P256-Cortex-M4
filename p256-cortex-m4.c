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

int P256_divsteps2_31(int delta, uint32_t f, uint32_t g, uint32_t res_matrix[4]);
void P256_matrix_mul_fg_9(uint32_t a, uint32_t b, const struct FGInteger fg[2], struct FGInteger *res);
void P256_matrix_mul_mod_n(uint32_t a, uint32_t b, const struct XYInteger xy[2], struct XYInteger *res);

void P256_to_montgomery(uint32_t aR[8], const uint32_t a[8]);
void P256_from_montgomery(uint32_t a[8], const uint32_t aR[8]);
void P256_mul_mod_p(uint32_t res[8], const uint32_t aR[8], const uint32_t bR[8]);
bool P256_check_range_p(const uint32_t a[8]);

bool P256_check_range_n(const uint32_t a[8]);
void P256_mul_mod_n(uint32_t res[8], const uint32_t a[8], const uint32_t b[8]);
void P256_add_mod_n(uint32_t res[8], const uint32_t a[8], const uint32_t b[8]);
void P256_mod_n_inv_vartime(uint32_t res[8], const uint32_t a[8]);
void P256_reduce_mod_n_32bytes(uint32_t res[8], const uint32_t a[8]);

void P256_select_point(uint32_t (*output)[8], uint32_t* table, uint32_t num_coordinates, uint32_t index);

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

#if include_p256_verify || include_p256_verify_prepared
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

#if include_p256_verify_prepared
// This table contains 1*2^128G, 3*2^128G, 5*2^128G, ... 15*2^128G in affine coordinates in montgomery form
static const uint32_t p256_basepoint_2_128_precomp[8][2][8] = {
{{0xbfe20925, 0x62a8c244, 0x8fdce867, 0x91c19ac3, 0xdd387063, 0x5a96a5d5, 0x21d324f6, 0x61d587d4},
{0xa37173ea, 0xe87673a2, 0x53778b65, 0x23848008, 0x5bab43e, 0x10f8441e, 0x4621efbe, 0xfa11fe12}},
{{0xb2335834, 0xc0f734a3, 0x90ef6860, 0x9526205a, 0x4e2bb0d, 0xcb8be717, 0x2f383fa, 0x2418871e},
{0x4082c157, 0xd7177681, 0x29c20073, 0xcc914ad0, 0xe587e728, 0xf186c1eb, 0x61bcd5fd, 0x6fdb3c22}},
{{0x2cf9d7c1, 0xcc7c4c1c, 0xee95e5ab, 0x1320886a, 0xbeae170c, 0xbb7b9056, 0xdbc0d662, 0xc8a5b250},
{0xc11d2303, 0x4ed81432, 0x1f03769f, 0x7da66912, 0x84539828, 0x3ac7a5fd, 0x3bccdd02, 0x14dada94}},
{{0xcbae2f70, 0x51b90651, 0x93aaa8eb, 0xefc4bc05, 0xdd1df499, 0x8ecd8689, 0x22f367a5, 0x1aee99a8},
{0xae8274c5, 0x95d485b9, 0x7d30b39c, 0x6c14d445, 0xbcc1ef81, 0xbafea90b, 0xa459a2ed, 0x7c5f317a}},
{{0xdeeaf52, 0x410dc6a9, 0x4c641c15, 0xb003fb02, 0x5bc504c4, 0x1384978c, 0x864a6a77, 0x37640487},
{0x222a77da, 0x5991bc6, 0x5e47eb11, 0x62260a57, 0xf21b432c, 0xc7af6613, 0xab4953e9, 0x22f3acc9}},
{{0xc24efc8, 0xd094277, 0xbef737a4, 0x349fd04, 0x514cdd28, 0x6d1c9dd2, 0x30da9521, 0x29c135ff},
{0xf78b0b6f, 0xea6e4508, 0x678c143c, 0x176f5dd2, 0x4be21e65, 0x8148418, 0xe7df38c4, 0x27f7525c}},
{{0xe4652f1d, 0x9faaccf5, 0xd56157b2, 0xbd6fdd2a, 0x6261ec50, 0xa4f4fb1f, 0x476bcd52, 0x244e55ad},
{0x47d320b, 0x881c9305, 0x6181263f, 0x1ca983d5, 0x278fb8ee, 0x354e9a44, 0x396e4964, 0xad2dbc0f}},
{{0x88a2ffe4, 0xfce01767, 0x28e169a5, 0xdc506a35, 0x7af9c93a, 0xea10861, 0x3fa0e08, 0x1ed24361},
{0xa3d694e7, 0x96eaaa92, 0xef50bc74, 0xc0f43b4d, 0x64114db4, 0xce6aa58c, 0x7c000fd4, 0x8218e8ea}}
};
#endif

#if include_fast_p256_basemult
#if fast_p256_basemult_tables != 2 && fast_p256_basemult_tables != 4 && fast_p256_basemult_tables != 8
#error "fast_p256_basemult_tables must be 2, 4 or 8"
#endif
// This contains fast_p256_basemult_tables tables, 8 points each in affine coordinates in montgomery form
// The first table contains these points:
// (2^192 - 2^128 - 2^64 - 1)G
// (2^192 - 2^128 - 2^64 + 1)G
// (2^192 - 2^128 + 2^64 - 1)G
// (2^192 - 2^128 + 2^64 + 1)G
// (2^192 + 2^128 - 2^64 - 1)G
// (2^192 + 2^128 - 2^64 + 1)G
// (2^192 + 2^128 + 2^64 - 1)G
// (2^192 + 2^128 + 2^64 + 1)G
// Table t contains the same points multiplied by 2^(t * 64 / fast_p256_basemult_tables)
// The tables are generated by tablegen.js
static const uint32_t p256_basepoint_precomp2[fast_p256_basemult_tables][8][2][8] =
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
#if fast_p256_basemult_tables == 8
{
{{0x9e082a81, 0x46f854fd, 0x715dbac6, 0x9dd1021a, 0xebe41989, 0x67e8da44, 0xff6a3235, 0xdf9003a6},
{0xec7e7f35, 0x35b8feac, 0x76395a83, 0xee45ed60, 0xae6fce90, 0x211b344e, 0x6ee12bde, 0x7c8790fe}},
{{0x3edfcf09, 0x98049e4e, 0x64181986, 0x919b30cb, 0xe08a3279, 0x56776df2, 0x7ae8d762, 0x222617c4},
{0x9d94169e, 0x7d7c6faa, 0x8c40d3fb, 0x2cfc046b, 0xbb1a6a24, 0x13895c95, 0xe97c0ba0, 0xa9c08992}},
{{0xdc1c2d31, 0x4f8ef895, 0x62d9677c, 0xfbc91726, 0x681a935e, 0x76a3b12f, 0xb875e29f, 0xbdb2804d},
{0x71bf8554, 0xab322454, 0x1213207c, 0xadbeb2f0, 0x697e8cdc, 0x7936b51b, 0x5fb41150, 0x9bd05efc}},
{{0x8057cca1, 0x4c93123, 0xbe89c98c, 0x413f0f23, 0x3a3f5e1, 0xab53079d, 0x74ae47ff, 0xeaffd9a5},
{0x810b5a31, 0xdbaa2ec, 0x79a97247, 0xd0396f4d, 0x169aa230, 0xcbcdbe19, 0xbe8bee16, 0x2b4aa27e}},
{{0x4ef6b9ca, 0x191537f1, 0xe8889d0d, 0x6814f084, 0xa6d7eccd, 0x4e1173f9, 0xfc2c75a9, 0x3db55f19},
{0xf4806696, 0x90571329, 0x9998cb4c, 0x9f984e0e, 0xd848ee44, 0x9881d2c5, 0xe0def8ec, 0x98914e45}},
{{0x5e67be83, 0x8e95735a, 0x3ca2c26f, 0x29299e73, 0xe8bf0e1d, 0x878f793e, 0x8a0e71b3, 0xa7129b3e},
{0xcb615159, 0x3b2ce4d0, 0xf1e33662, 0x7f64f020, 0xfe55b539, 0xad41222f, 0x6ed8726f, 0x1f21fad0}},
{{0x631e756b, 0x5d3c1ed1, 0x54b6a1ba, 0xdf2a16c3, 0xe7078722, 0xa4e3cbab, 0xfa5cbe02, 0x47686e2d},
{0x6e453742, 0xa469a3f3, 0x9e6122a, 0xa1b429c9, 0xc7e1fa0b, 0x8497ef8, 0xa6bf6868, 0x190b9fdf}},
{{0xfc2b4e00, 0xf95684f7, 0xef571f04, 0x114521ac, 0x4abb78e3, 0x48d9b5ea, 0xda9891d8, 0x3df9c7ba},
{0x944cab81, 0x1ca68374, 0x76fdb53f, 0x98453f5b, 0xb1cd8a0e, 0x995789b8, 0xe42ce845, 0xafe5e48e}}
},
#endif
#if fast_p256_basemult_tables >= 4
{
{{0xa0cf2a60, 0x716a131b, 0xd73e9f7f, 0xc4b28b8f, 0xecda039b, 0x9d701e9f, 0x113be564, 0x5a53bce0},
{0x2c6a1a74, 0x81d8e13c, 0x5fab4ded, 0x20ad3176, 0xbe1f317f, 0xd2dfdd9e, 0x3f203408, 0x72c479ae}},
{{0xa271449a, 0x61e8041, 0xbee25a60, 0x90debebd, 0x980a84c2, 0x43879d6e, 0x120732a4, 0x474895c9},
{0x6f733bd9, 0x93866f31, 0x98d57052, 0xae4fe2a, 0x45c3a453, 0x37c4c754, 0x885fd2c7, 0x55be778c}},
{{0x21e72751, 0xa95fa0a9, 0x5fb0f501, 0x1a21825b, 0x24a58594, 0xd62d8de4, 0x5c5426b6, 0xd328e53a},
{0xa6d77759, 0xd29204e6, 0x70f63559, 0x58202b29, 0x1a588728, 0x5cb70874, 0x93835d5a, 0x7a291685}},
{{0x7206cfa7, 0xf46e58c1, 0xacc7943a, 0x48019f8f, 0x7c51adc3, 0x72c32bd5, 0xeb447ce7, 0x12337f5f},
{0xe140d79e, 0x74cf7363, 0xcb11ecbd, 0x2798fc68, 0x56a57c37, 0xf1a1fd5d, 0xfd25e4a2, 0xcc2ac48}},
{{0xc7ef418d, 0xecd440ee, 0x8b0db916, 0x40c31176, 0x45fa643d, 0x6a16c028, 0x88da48a, 0xe845e7ce},
{0x2b9c8597, 0x746270a2, 0x7d9bcca0, 0x7243751e, 0xf9f1af57, 0x6eba4e1f, 0x6e4f3702, 0x27ac551e}},
{{0xd6ae07b0, 0xf7f7a33b, 0xa71f4ba0, 0xd2973a8c, 0x775dad7a, 0x945e2405, 0x28799154, 0x836c634c},
{0xd542f1f9, 0xbbe69c99, 0x5942e376, 0xd5520207, 0x48e3beb0, 0x298d5693, 0x946e17fd, 0x41c8be29}},
{{0x1145f5e1, 0xbfcb9497, 0xb15fb95, 0x482b3b45, 0x54165ca2, 0x1b8d3b1f, 0x6e4906cb, 0xb4ddb9e5},
{0x7eed1f05, 0xf4e2c211, 0xf08cc5d0, 0xc6f02cb7, 0x76dcdeb8, 0xe80620bf, 0x9578cc66, 0x1a6484c9}},
{{0xfea91e5, 0x85ff4f35, 0xaf91bda6, 0x32954682, 0x8eeaafca, 0xfe1f173d, 0x2da4161b, 0x5badab63},
{0xbf84e659, 0x2107bc51, 0xad86caa0, 0xf4368698, 0x6e9fbe0e, 0x84ad8cf4, 0xb45a2551, 0xf7f134ad}}
},
#endif
#if fast_p256_basemult_tables == 8
{
{{0xd8663cc, 0xad90249e, 0xfee9cf9a, 0x10d85cd, 0x43671cc9, 0xe0f6962b, 0x2a1fa2a3, 0xf0302ce8},
{0x3352adad, 0xe64b02c9, 0x6c542133, 0xb9147567, 0x74377386, 0x46f67ddf, 0x9a01c061, 0xb0b4cc07}},
{{0x9f3866e7, 0x9ded8dd6, 0xa5d85c40, 0x87b1122e, 0xf65119cd, 0x6e5f9fcb, 0xc329c544, 0x3aeb0e43},
{0xf04b0eaa, 0x908b8193, 0xa773717a, 0xfecd4f31, 0x34802f1a, 0x6d77d12e, 0xb41dfd35, 0x8a8677c8}},
{{0x650050e5, 0x8acc067f, 0x90774b85, 0x854cfcfd, 0x5a50bebe, 0x7d0a2869, 0x2103b87f, 0x18bb26fe},
{0x615b0fe8, 0xbe46f8e1, 0x7579e67c, 0xd91b49cc, 0xfbcb3e13, 0xc7893cbe, 0x408cc627, 0x3b33bff6}},
{{0xc9966b30, 0xc57ade30, 0x7329360b, 0xaff64caf, 0x142c0ecc, 0xa3e14295, 0x557fb857, 0x17d5f5ea},
{0xde290561, 0xdf930851, 0x2f61fe61, 0xf62497a3, 0x45f1869b, 0x353075d7, 0x9be5d4ab, 0xf74c636c}},
{{0x8d02bf56, 0xcdbfeae, 0xcd3eb0e6, 0xecc8a6de, 0xd85c5f47, 0xcfc37864, 0x42e9b78b, 0x491841e5},
{0xb7394ad2, 0xd7c65790, 0xb935e459, 0x8036afc2, 0x6a66a491, 0x293ce02c, 0x6c8cc205, 0xc7ad5654}},
{{0xd26d3997, 0x4a19dba5, 0x53352a05, 0x65cfb89b, 0x8259a9bf, 0x7b99f4a0, 0x665347ec, 0x483587ce},
{0xb0747813, 0xc0b144b6, 0xf8d7a63a, 0x4398cdff, 0x541c6c8b, 0x7cb892a9, 0x7f52010a, 0xb256bfab}},
{{0xd87d624c, 0xc517fe72, 0x819e1ad9, 0x15ca5be5, 0xf265fd05, 0xc6e6af63, 0x5dd78b13, 0x801678},
{0xc1f16d06, 0x6496b79e, 0x44e2a635, 0x7840bc79, 0xdeddf768, 0x42493826, 0xcc9bdb65, 0x92668133}},
{{0x1610cd52, 0xed88310, 0x236a1040, 0xda4dc01, 0x924a7203, 0x427ca1f2, 0xaafd3d7d, 0xa4737b77},
{0x96a5ba97, 0x66275220, 0x7ee66858, 0x87c05743, 0x37da5d39, 0xaeb7ce88, 0xd4ae3b19, 0xee946502}}
},
#endif
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
},
#if fast_p256_basemult_tables == 8
{
{{0xa06383fa, 0x9ac68e8a, 0xaebd7360, 0xd4b8c399, 0x8b304987, 0x153a9253, 0x2bf3b560, 0x27f30d4f},
{0x56f7d761, 0xae00b215, 0xe2d5a6e0, 0x54aeb406, 0x1bd5f230, 0x20081daf, 0x43ef01a3, 0xd625b7b}},
{{0xc2688d91, 0x8a2f93e1, 0x7196e817, 0xa1446da8, 0xf21a0e9b, 0x262a18bb, 0xc2c916b, 0x48a2c8a0},
{0x221d2f4c, 0xeedf3b53, 0xcf72db92, 0x8522eb14, 0xd4a963f, 0x1fa89b53, 0x978b8a61, 0xd46681b2}},
{{0x33968d53, 0xb62ee1d, 0x2aec9108, 0x3ee35612, 0x79675936, 0xb7c07a82, 0x9031a745, 0x303d3a0e},
{0x2a4f2b1f, 0x2462219, 0xa5cbb50, 0x5d85e01c, 0x6053fd99, 0x1382884a, 0xde960f0c, 0x7bbad6a8}},
{{0x94cb56f, 0x7f9e418f, 0xb465efd0, 0x58517960, 0x24c18e1d, 0xcf33cbda, 0xc0baf52a, 0x6f9deb23},
{0xcfc63c2, 0xba72f95c, 0xe268b866, 0x529c7a01, 0xd2e668c5, 0x2d716f12, 0xd8cf0b0f, 0xc6f6d7a2}},
{{0xec10342f, 0x51824670, 0x52c2a183, 0x5d08cf49, 0x830e1806, 0xaf6a4ed2, 0xbec885f9, 0x40ee181d},
{0xc1d9e055, 0x7c4a74af, 0x8504a968, 0xe689d647, 0xf9a1b90d, 0xcac18384, 0x3dd252e9, 0x1cd8045e}},
{{0x8a563cf2, 0x5c8aa2e3, 0xf320d88d, 0xb9946bcf, 0x94c44265, 0x2b7b8e10, 0xdac53e97, 0x7a8015b},
{0xb00ab40a, 0xcf1fbaf4, 0x507717d3, 0x5a5006fd, 0x68eb735d, 0x7ff8d6ed, 0x713f846a, 0x8a03e1ea}},
{{0xab169f6c, 0x29354fec, 0xbcc7ddac, 0x449cbc9, 0x24377583, 0x6ab17fa2, 0x7f9e0ab2, 0x34130c2c},
{0xa53da9cb, 0x715ba5da, 0x844f48f1, 0x1af6f4cf, 0xb7cc43ab, 0xb0babed0, 0x1ccf3c29, 0x387aa6eb}},
{{0xb2630de5, 0xbfca3418, 0x86980a16, 0xdb52a230, 0x128dd83a, 0x732a1969, 0xb3f0c36e, 0x38193f06},
{0xa449a0ef, 0xdef6b620, 0x69f5de63, 0xf2aa5615, 0x77945df2, 0x87325c3c, 0x30e90c8d, 0xe0889276}}
},
#endif
#if fast_p256_basemult_tables >= 4
{
{{0x74b3b2b5, 0x349d63fe, 0xe3643fda, 0x455ffff, 0xb5554b65, 0x13078808, 0x7aef08a2, 0x70617828},
{0x4b19cb81, 0xba122484, 0x9ec65bb4, 0xa14d037b, 0x3e95e388, 0x5b48ef68, 0xa9b3ec25, 0x8b773836}},
{{0x2fe5b0c0, 0xfb69ea68, 0x28ae8ead, 0x11411e27, 0x22a17fa4, 0x46f7861a, 0x8e0a2b46, 0x2d46e989},
{0x9e09f032, 0x477da4c2, 0xfc369acd, 0x3ba21660, 0x7b689343, 0xc8699cc6, 0x894efff, 0x603f8177}},
{{0x9a053ae6, 0x6d94d5b3, 0xb34174e5, 0x2ef99da1, 0x1cd3c6a5, 0xf23d766a, 0xc3bfc938, 0xc0a94b4a},
{0x7527a76d, 0x2cf2038e, 0xf82ecb1a, 0x114f7164, 0xf8cdfcf5, 0x1c74af3b, 0x314d984d, 0x10295c08}},
{{0xd6d17ebf, 0xbe0dee24, 0x4b22a7f7, 0x745c4ca7, 0x692980d4, 0x5e2bda17, 0xa522844e, 0xdc04a3fa},
{0xe72fd0cd, 0x960d7da9, 0x4c79a612, 0xca50bb85, 0xa34c6590, 0x4e75e17c, 0xbd21d868, 0xda0a7bbf}},
{{0xa32a3534, 0xaa0e7e8e, 0xeee98ca9, 0x35989737, 0x2b24fb98, 0x3e6b5744, 0x1c036833, 0x4171b92a},
{0x4ce6029, 0x24ceea75, 0x247378cf, 0x2f9288d8, 0x76738cf7, 0xff809156, 0x7a393c21, 0xd4cea73c}},
{{0x8f7afb46, 0xa33282e2, 0xae457ee9, 0x81410b2c, 0xb94f9def, 0xb23d45cb, 0xb0426903, 0x3d1533e},
{0x26071972, 0x539c2d8f, 0x9c939f4f, 0xd993ee4f, 0x9598d171, 0x309bfae0, 0xb4379e17, 0x509a4fc9}},
{{0x35b74ec6, 0x52d6dcc5, 0x52ceaf16, 0x2b6ff7c9, 0x2f906ed7, 0x5343f995, 0x3e298b6a, 0x3ea6bab0},
{0x5b08aa26, 0x9be35ac2, 0x6d8b0592, 0x1307a29b, 0xed88f422, 0x9f4c192, 0xa3fe4249, 0x8877e81f}},
{{0x32237e81, 0x8de08805, 0x874dfaee, 0xf43684ec, 0x88bef633, 0xfdba26b9, 0x5d2a9c91, 0xac299404},
{0xa96659e1, 0xeea6a5a0, 0xd25ec31a, 0xe74a555d, 0xd7d5a482, 0x8663b8f1, 0x1b5845e4, 0x50b490d7}}
},
#endif
#if fast_p256_basemult_tables == 8
{
{{0x3fa22429, 0x9869be54, 0xbbf78f63, 0x5e52255c, 0x4e24090e, 0x9c1dbbe9, 0x8a64f78a, 0xd165c574},
{0xcf5480ce, 0xe686601d, 0x2aee181d, 0x9b58fe72, 0xe7c83abf, 0xd4076b8c, 0xd4b8243, 0x65f73d73}},
{{0x545590f9, 0xc0b53540, 0x762b3362, 0x9cbe9f3f, 0xbaaea52f, 0x17e3ba8, 0xf4cf95a0, 0x91e9fc11},
{0xdb8cd55e, 0xa60667cd, 0xea3935b7, 0x7688c370, 0x8c786c62, 0xdf95b116, 0x6e76adb1, 0x4cb4a098}},
{{0x64ff6eb, 0x38d18ad1, 0xbf7d1595, 0xe3d9d02e, 0xf77bcfa6, 0xd9b7b13c, 0xa1111a33, 0xfd73a945},
{0x40ea70f1, 0x17a71458, 0x58f46306, 0xc18eb84d, 0xe78dfce8, 0x345a99f2, 0x6f7f41d3, 0x8a9034e9}},
{{0xe24343dc, 0xc06c2221, 0xd17db1e9, 0x2bdafe82, 0x38e05228, 0x6f567d0e, 0xdb89fc30, 0x3121e245},
{0x7e51ea7c, 0x1786b0f1, 0x3f28a2d2, 0xb18455c1, 0x32c9b213, 0xe0f57c31, 0x9c654649, 0x1783ef6a}},
{{0x7bad7cb8, 0x7e4957ad, 0xc0a7f69e, 0xfe0e56f0, 0xd5ff9935, 0x106c90c2, 0x7df182af, 0xbdd07574},
{0x8b8cdf77, 0xc6714c1b, 0xa4d35b1b, 0x4a8ebfb6, 0xe2b8698a, 0xf89b5906, 0xd65fee09, 0x2b271a08}},
{{0xe84087b3, 0x66a0e646, 0x16e17b57, 0xa36ee17c, 0x10fe35fe, 0x13d12bfe, 0xde3d428, 0xe7ae32},
{0x16aeb17e, 0x290ecc37, 0x23c04210, 0x9a8e7cd4, 0xb05566a0, 0x62a37db3, 0xdab78bca, 0x18b59474}},
{{0x1a7036b0, 0x5a65bc69, 0x46e8365, 0x2a8c78a8, 0x2efeb635, 0x26e27cb4, 0x72d244b3, 0xaa882899},
{0x22406e08, 0xeb737249, 0xdda1dc6c, 0x7b1dfbf3, 0x779dbde7, 0x9daa7156, 0x7e8e404f, 0xb399596c}},
{{0xe29b03, 0xde4cf2be, 0x5bf6b853, 0xdc38c4e3, 0x62b93d98, 0x4af556a8, 0xa4e5db9d, 0x493f4823},
{0xc3fcc6cc, 0x4bf133b6, 0xbcd26660, 0xb83ecd49, 0xf9b56b20, 0x313c78b6, 0x1715e3b2, 0x92c4010e}}
},
#endif
};
#endif

#if include_p256_verify || include_p256_verify_prepared || include_p256_sign
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

#if include_p256_verify || include_p256_verify_prepared
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
        
        // Decode f and g into two's complement representation and use the lowest 32 bits in the P256_divsteps2_31 calculation
        uint32_t negate_f = state[i % 2].fg[0].flip_sign;
        uint32_t negate_g = state[i % 2].fg[1].flip_sign;
        delta = P256_divsteps2_31(delta, (state[i % 2].fg[0].signed_value[0] ^ negate_f) - negate_f, (state[i % 2].fg[1].signed_value[0] ^ negate_g) - negate_g, matrix);
        
        // "Jump step", calculates the new f and g values that applies after 31 divstep2 iterations
        P256_matrix_mul_fg_9(matrix[0], matrix[1], state[i % 2].fg, &state[(i + 1) % 2].fg[0]);
        P256_matrix_mul_fg_9(matrix[2], matrix[3], state[i % 2].fg, &state[(i + 1) % 2].fg[1]);
        
        // Iterate the result vector
        // Due to montgomery multiplication inside this function, each step also adds a 2^-32 factor
        P256_matrix_mul_mod_n(matrix[0], matrix[1], state[i % 2].xy, &state[(i + 1) % 2].xy[0]);
        P256_matrix_mul_mod_n(matrix[2], matrix[3], state[i % 2].xy, &state[(i + 1) % 2].xy[1]);
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
    P256_select_point(current_point, (uint32_t*)table, 3, e[63] >> 1);
    #else
    memcpy(current_point, table[e[63] >> 1], 96);
    #endif
    
    for (uint32_t i = 63; i --> 0;) {
        for (int j = 3; j >= 0; j--) {
            P256_double_j(current_point, (constarr)current_point);
        }
        uint32_t selected_point[3][8];
        #if has_d_cache
        P256_select_point(selected_point, (uint32_t*)table, 3, abs_int(e[i]) >> 1);
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

#define get_bit(arr, i) (((arr)[(i) / 32] >> ((i) % 32)) & 1)

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
    
    // We then form the scalars abs(s[j] + s[j+64]*2^64 + s[j+128]*2^128 + s[j+192]*2^192)*2^(d * floor(j / d)) for different 0 <= j < 64,
    // where d = 64 / fast_p256_basemult_tables.
    // Each scalar times G has already been precomputed in p256_basepoint_precomp2.
    // That way we only need d - 1 point doublings (31, 15 or 7) and 63 point additions.
    
    const uint32_t d = 64 / fast_p256_basemult_tables;
    uint32_t current_point[3][8];
    uint32_t selected_point[2][8];
    
    #if !has_d_cache
    // Load table into RAM, for example if the the table lies on external memory mapped flash, which can easily be intercepted.
    uint32_t precomp[fast_p256_basemult_tables][8][2][8];
    memcpy(precomp, p256_basepoint_precomp2, sizeof(p256_basepoint_precomp2));
    #endif
    
    // The first point uses s[63], s[127] and s[191] (bits 64, 128 and 192) with the last table, and is not negated since s[255] = 1.
    {
        uint32_t mask = get_bit(scalar2, 64) | (get_bit(scalar2, 128) << 1) | (get_bit(scalar2, 192) << 2);
        #if has_d_cache
        P256_select_point(current_point, (uint32_t*)p256_basepoint_precomp2[fast_p256_basemult_tables - 1], 2, mask);
        #else
        memcpy(current_point, precomp[fast_p256_basemult_tables - 1][mask], 64);
        #endif
        memcpy(current_point[2], one_montgomery, 32);
    }
    
    for (uint32_t i = d; i --> 0;) {
        uint32_t t = fast_p256_basemult_tables;
        if (i == d - 1) {
            t--;
        } else {
            P256_double_j(current_point, (constarr)current_point);
        }
        while (t --> 0) {
            // s[i + t * d + 64 * k] is given by bit pos + 64 * k of scalar2, which is bit pos of scalar2 + 2 * k
            uint32_t pos = i + t * d + 1;
            uint32_t mask = get_bit(scalar2, pos) | (get_bit(scalar2 + 2, pos) << 1) | (get_bit(scalar2 + 4, pos) << 2);
            uint32_t sign = get_bit(scalar2 + 6, pos) - 1; // positive: 0, negative: -1
            mask = (mask ^ sign) & 7;
            #if has_d_cache
            P256_select_point(selected_point, (uint32_t*)p256_basepoint_precomp2[t], 2, mask);
            #else
            memcpy(selected_point, precomp[t][mask], 64);
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
    #if !(include_p256_verify || include_p256_verify_prepared)
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

#if include_p256_verify_prepared
bool p256_verify_prepare(struct VerifyPrecomp *ctx, const uint32_t public_key_x[8], const uint32_t public_key_y[8]) {
    do {
        if (!P256_check_range_p(public_key_x) || !P256_check_range_p(public_key_y)) {
            break;
        }
        
        // Jacobian points P, 3P, 5P, ..., 15P, for P = Q at index 0 to 7 and P = 2^128*Q at index 8 to 15, where Q is the public key.
        uint32_t points[16][3][8];
        P256_to_montgomery(points[0][0], public_key_x);
        P256_to_montgomery(points[0][1], public_key_y);
        memcpy(points[0][2], one_montgomery, 32);
        
        if (!P256_point_is_on_curve(points[0][0], points[0][1])) {
            break;
        }
        
        P256_double_j(points[8], (constarr)points[0]);
        for (int i = 1; i < 128; i++) {
            P256_double_j(points[8], (constarr)points[8]);
        }
        
        for (int t = 0; t < 16; t += 8) {
            P256_double_j(points[t + 7], (constarr)points[t]);
            for (int i = t + 1; i < t + 8; i++) {
                memcpy(points[i], points[t + 7], 96);
                P256_add_sub_j(points[i], (constarr)points[i - 1], 0, 0);
            }
        }
        
        // Convert all points to affine coordinates using a single field inversion (Montgomery's trick).
        // The products Z_0*Z_1*...*Z_i are kept in the y coordinate of ctx->table[i] until point i is converted.
        memcpy(ctx->table[0][1], points[0][2], 32);
        for (int i = 1; i < 16; i++) {
            P256_mul_mod_p(ctx->table[i][1], ctx->table[i - 1][1], points[i][2]);
        }
        
        // The inverse of a is the affine x coordinate X/Z^2 of the jacobian point (X, Y, Z) = (a, a, a).
        uint32_t inv[8], unused[8], a[3][8];
        memcpy(a[0], ctx->table[15][1], 32);
        memcpy(a[1], ctx->table[15][1], 32);
        memcpy(a[2], ctx->table[15][1], 32);
        P256_jacobian_to_affine(inv, unused, (constarr)a);
        
        for (int i = 15; i >= 0; i--) {
            // Here inv = 1/(Z_0*Z_1*...*Z_i)
            uint32_t z_inv[8], z_inv_pow[8];
            if (i > 0) {
                P256_mul_mod_p(z_inv, inv, ctx->table[i - 1][1]);
                P256_mul_mod_p(inv, inv, points[i][2]);
            } else {
                memcpy(z_inv, inv, 32);
            }
            P256_mul_mod_p(z_inv_pow, z_inv, z_inv);
            P256_mul_mod_p(ctx->table[i][0], points[i][0], z_inv_pow);
            P256_mul_mod_p(z_inv_pow, z_inv_pow, z_inv);
            P256_mul_mod_p(ctx->table[i][1], points[i][1], z_inv_pow);
        }
        return true;
    } while (false);
    
    memset(ctx, 0, sizeof(struct VerifyPrecomp));
    return false;
}

// Adds (digit > 0) or subtracts (digit < 0) point abs(digit)/2 of an affine table to/from the jacobian point,
// where the table contains the odd multiples 1P, 3P, ..., 15P.
static void add_slide_digit(uint32_t point[3][8], const uint32_t (*table)[2][8], signed char digit) {
    if (digit > 0) {
        P256_add_sub_j(point, table[digit/2], 0, 1);
    } else if (digit < 0) {
        P256_add_sub_j(point, table[(-digit)/2], 1, 1);
    }
}

bool p256_verify_prepared(const struct VerifyPrecomp *ctx, const uint8_t* hash, uint32_t hashlen_in_bytes, const uint32_t r[8], const uint32_t s[8]) {
    if (!P256_check_range_n(r) || !P256_check_range_n(s)) {
        return false;
    }
    
    // Just make sure user did not input an obviously invalid precomp, such as the zeroed one from a failed p256_verify_prepare
    if (!P256_point_is_on_curve(ctx->table[0][0], ctx->table[0][1])) {
        return false;
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
    
    signed char slide_bp[257], slide_pk[257];
    slide_257(slide_bp, (uint8_t*)u1);
    slide_257(slide_pk, (uint8_t*)u2);
    
    // u1*G + u2*Q is computed as a sum over i of 2^i*(slide_bp[i]*G + slide_bp[i + 128]*2^128*G + slide_pk[i]*Q + slide_pk[i + 128]*2^128*Q),
    // so only 129 doublings are needed.
    uint32_t cp[3][8] = {0};
    
    for (int i = 128; i >= 0; i--) {
        P256_double_j(cp, (constarr)cp);
        add_slide_digit(cp, p256_basepoint_2_128_precomp, slide_bp[i + 128]);
        add_slide_digit(cp, ctx->table + 8, slide_pk[i + 128]);
        if (i < 128) {
            add_slide_digit(cp, p256_basepoint_precomp, slide_bp[i]);
            add_slide_digit(cp, ctx->table, slide_pk[i]);
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
