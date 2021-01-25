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

#ifndef P256_CORTEX_M4_H
#define P256_CORTEX_M4_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "p256-cortex-m4-config.h"

/*

Implementation of P-256 Elliptic Curve operations for 32-bit ARMv7E-M processors or later.

The functions below have the following conventions:
- Arrays of type uint32_t represent 256-bit integers, stored using little endian byte order on a 4-byte alignment.
- Pointer/array parameters are input parameters when they are const and output parameters when they are not
    const, unless otherwise stated.
- All functions that take a public key as parameter will validate that the public key corresponds to a valid
    point and return false if validation fails.
- When a function returns false, the output parameters, if any, will not contain valid data and should hence
    not be inspected.
- There are no checks for null pointers, unaligned uint32_t-pointers, invalid private keys etc.

If there is a need to convert a big endian byte string to an array of little endian uint32_t integers or vice
versa, the p256_convert_endianness function may be used for this purpose.

Note: code that processes secret data runs in constant time, in order to mitigate side channel attacks.

*/

/**
 * Converts endianness by reversing the input value.
 *
 * The output and input pointers may refer to the same location and have no alignment requirements.
 */
void p256_convert_endianness(void* output, const void* input, size_t byte_len);

#if include_p256_verify
/**
 * Verifies an ECDSA signature.
 *
 * Returns true if the signature is valid for the given input, otherwise false.
 */
bool p256_verify(const uint32_t public_key_x[8], const uint32_t public_key_y[8],
                 const uint8_t* hash, uint32_t hashlen_in_bytes,
                 const uint32_t r[8], const uint32_t s[8])
                 __attribute__((warn_unused_result));
#endif

#if include_p256_sign
/**
 * Creates an ECDSA signature.
 *
 * The parameter "k" shall consist of a 256-bit random integer value. This random value MUST be generated from
 * a cryptographically secure random number generator, and MUST be unique for every pair of message hash and
 * private key.
 *
 * With a small probability (~ 2^-32), this function will fail and return false for the given "k" and this
 * function MUST in that case be called again with a new random "k", until true is returned. This is in line
 * with the ECDSA standard.
 *
 * As an alternative to using a random "k", "k" might be derived deterministically from the input, using a
 * sophisticated hash construction such as RFC 6979, or e.g. by hashing the private key, message hash and a
 * retry counter, using a secure hash function such as SHA-256.
 */
bool p256_sign(uint32_t r[8], uint32_t s[8],
               const uint8_t* hash, uint32_t hashlen_in_bytes,
               const uint32_t private_key[8], const uint32_t k[8])
               __attribute__((warn_unused_result));

/**
 * Sign precomputation state.
 *
 * The content shall be treated as opaque to the API user and shall not be inspected or modified.
 */
struct SignPrecomp {
    uint32_t r[8];
    uint32_t k_inv[8];
};

/**
 * Creates an ECDSA signature, using a two-step procedure.
 *
 * This function performs the first of two steps, and accounts for 99% of the time spent for generating an
 * ECDSA signature.
 *
 * By splitting up into two steps, most of the work could be spent before deciding what message to sign, or
 * which private key to use.
 *
 * The parameter "k" shall consist of a 256-bit random integer value. This random value MUST be generated from
 * a cryptographically secure random number generator, and MUST be unique for every pair of message hash and
 * private key.
 *
 * With a small probability (~ 2^-32), this function will fail and return false for the given "k" and this
 * function MUST in that case be called again with a new random "k", until true is returned. This is in line
 * with the ECDSA standard.
 *
 * As an alternative to using a random "k", "k" might be derived deterministically from the input, using a
 * sophisticated hash construction such as RFC 6979, or e.g. by hashing the private key, message hash and a
 * retry counter, using a secure hash function such as SHA-256.
 *
 * The "result" parameter will contain the computed state, that is later to be passed to p256_sign_step2.
 * A result state MUST NOT be reused for generating multiple signatures.
 */
bool p256_sign_step1(struct SignPrecomp *result, const uint32_t k[8]) __attribute__((warn_unused_result));

/**
 * Second step of creating an ECDSA signature, using a two-step procedure.
 *
 * This function performs the second of two steps, and accounts for the last 1% of the time spent for generating
 * an ECDSA signature.
 *
 * The "sign_precomp" parameter shall contain a pointer to a state generated by p256_sign_step1.
 *
 * With a small probability (~ 2^-256), this function will fail, due to the given "k" from the first step is
 * not compatible with the rest of the input, and return false. In this case, the procedure MUST be started
 * over from step 1 with a new random "k".  This is in line with the ECDSA standard. Otherwise true is returned
 * and the signature is placed in "r" and "s".
 *
 * When this function returns, "sign_precomp" is also zeroed out and may hence not be reused.
 */
bool p256_sign_step2(uint32_t r[8], uint32_t s[8], const uint8_t* hash, uint32_t hashlen_in_bytes,
                     const uint32_t private_key[8], struct SignPrecomp *sign_precomp)
                     __attribute__((warn_unused_result));
#endif

#if include_p256_keygen
/**
 * Calculates the public key from a given private key for use by either ECDSA or ECDH.
 *
 * The private key shall be taken from a random value that MUST have been generated by a cryptographically
 * secure random number generator that generates 256 random bits. This function validates that the private key
 * lies in the accepted range 1 to n-1, where n is the order of the elliptic curve, and returns true only if
 * this validation succeeds. If random value is out of that range, false is returned and in this case a new
 * random value needs to be generated and this function MUST be called again until true is returned.
 *
 * The public key is created by performing a scalar multiplication of the private key and the base point of
 * the curve.
 *
 * Only use a keypair for either ECDSA or ECDH, not both, and don't use the private key for any other purposes.
 */
bool p256_keygen(uint32_t public_key_x[8], uint32_t public_key_y[8],
                 const uint32_t private_key[8])
                 __attribute__((warn_unused_result));
#endif

#if include_p256_ecdh
/**
 * Generates the shared secret according to the ECDH standard.
 *
 * The shared secret parameter will contain the big endian encoding for the x coordinate of the scalar
 * multiplication of the private key and the input point (other's public key), if the function succeeds.
 *
 * If the other's public key point does not lie on the curve, this function fails and false is returned.
 * Otherwise, shared secret is calculated and true is returned.
 *
 * NOTE: The return value MUST be checked since the other's public key point cannot generally be trusted.
 */
bool p256_ecdh_calc_shared_secret(uint8_t shared_secret[32], const uint32_t private_key[8],
                                  const uint32_t others_public_key_x[8], const uint32_t others_public_key_y[8])
                                  __attribute__((warn_unused_result));
#endif

#if include_p256_raw_scalarmult_base
/**
 * Raw scalar multiplication by the base point of the elliptic curve.
 *
 * This function can be used to implement custom algorithms using the P-256 curve.
 *
 * This function validates that the scalar lies in the accepted range 1 to n-1, where n is the order of the
 * elliptic curve, and returns true only if this validation succeeds. Otherwise false is returned.
 */
bool p256_scalarmult_base(uint32_t result_x[8], uint32_t result_y[8], const uint32_t scalar[8]);
#endif

#if include_p256_raw_scalarmult_generic
/**
 * Raw scalar multiplication by any point on the elliptic curve.
 *
 * This function can be used to implement custom algorithms using the P-256 curve.
 *
 * This function validates all inputs and proceeds only if the scalar is within the range 1 to n-1, where n
 * is the order of the elliptic curve, and the input point's coordinates are each less than the order of
 * the prime field. If validation succeeds, true is returned. Otherwise false is returned.
 */
bool p256_scalarmult_generic(uint32_t result_x[8], uint32_t result_y[8],
						     const uint32_t scalar[8], const uint32_t in_x[8], const uint32_t in_y[8]);
#endif

// These functions create a big endian octet string representation of a point according to the X.92 standard.

#if include_p256_to_octet_string_uncompressed
/**
 * Uncompressed encoding: "04 || Px || Py".
 */
void p256_point_to_octet_string_uncompressed(uint8_t out[65], const uint32_t x[8], const uint32_t y[8]);
#endif

#if include_p256_to_octet_string_compressed
/**
 * Compressed encoding: "02 || Px" if Py is even and "03 || Px" if Py is odd.
 */
void p256_point_to_octet_string_compressed(uint8_t out[33], const uint32_t x[8], const uint32_t y[8]);
#endif

#if include_p256_to_octet_string_hybrid
/**
 * Hybrid encoding: "06 || Px || Py" if Py is even and "07 || Px || Py" if Py is odd (a pretty useless encoding).
 */
void p256_point_to_octet_string_hybrid(uint8_t out[65], const uint32_t x[8], const uint32_t y[8]);
#endif

#if include_p256_decode_point || include_p256_decompress_point
/**
 * Decodes a point according to the three encodings above.
 *
 * include_p256_decode_point: first byte is "04", "06" or "07" and input length is 65 bytes
 * include_p256_decompress_point: first byte is "02" or "03" and input length is 33 bytes
 *
 * Returns true if the input string confirms to a valid encoding and the point lies on the curve,
 * otherwise false.
 *
 * NOTE: The return value MUST be checked in case the point is not guaranteed to lie on the curve (e.g. if it
 * is received from an untrusted party).
 */
bool p256_octet_string_to_point(uint32_t x[8], uint32_t y[8],
                                const uint8_t* input, uint32_t input_len_in_bytes)
                                __attribute__((warn_unused_result));
#endif

#endif
