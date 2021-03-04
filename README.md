# P256-Cortex-M4
P256 ECDH and ECDSA for Cortex-M4, Cortex-M33 and other 32-bit ARM processors

This library implements highly optimimzed assembler versions for the NIST P-256 (secp256r1) elliptic curve for Cortex-M4/Cortex-M33. While optimized for these processors, it works on other newer 32-bit ARM processors as well.

The DSP extension CPU feature is required for Cortex-M33.

### API

For full API documentation, see the header file `p256-cortex-m4.h`.

### How to use

To use it in your project, add the following files to your project: `p256-cortex-m4.h`, `p256-cortex-m4-config.h`, `p256-cortex-m4.c`. Then add _only_ one of the asm files that suits you best as a compilation unit to your project. If you use Keil, add `p256-cortex-m4-asm-keil.s` as a source file and add `--cpreproc` to "Misc Controls" under Options -> Asm for the file. If you use GCC, add `p256-cortex-m4-asm-gcc.S` to your Makefile just like any other C source file.

To only compile in the features needed, the file `p256-cortex-m4-config.h` can be modified to include only specific algorithms. If used on a Cortex-A processor, the `has_d_cache` setting shall also be enabled in order to prevent side-channel attacks. There are also optimization options to trade code space for performance. The same options can also be defined directly at the command line when compiling, using e.g. `-Dinclude_p256_sign=0` to omit the code for creating a signature.

### Examples

The library does not include a hash implementation (used during sign and verify), nor does it include a secure random number generator (used during keygen and sign). These functions must be implemented externally. Note that the secure random number generator must be for cryptographic purposes. In particular, `rand()` from the C standard library must not be used, while `/dev/urandom`, as can be found on many Unix systems, is compliant.

Note: all `uint32_t` arrays represent 256-bit integers in little-endian byte order (native to the CPU), located at a 4-byte alignment byte boundary. The `uint8_t` arrays either represent pure byte strings, or integers in big-endian byte order (no alignment requirements). When interacting with other libraries, make sure to carefully understand the data format used by those libraries. Some data conversion routines for easier interopability are included in the API.

#### ECDSA/ECDH Keygen

Generate a key pair for either ECDSA or ECDH (a key pair should not be used for both purposes).

```C
uint32_t pubkey_x[8], pubkey_y[8], privkey[8];
do {
    generate_secure_random_data(privkey, sizeof(privkey));
} while (!p256_keygen(pubkey_x, pubkey_y, privkey));
```

The result will now be contained in `pubkey_x`, `pubkey_y` and `privkey` (little-endian).

#### ECDSA Sign

In this example, SHA-256 is used as hash algorithm.

```C
// Input values
uint8_t message[] = ...;
size_t message_len = ...;
uint32_t privkey[8] = ...;

// Output values (the signature)
uint32_t signature_r[8], signature_s[8];

uint8_t hash[32];
sha256_hash(message, message_len, hash);

uint32_t k[8]; // must be kept secret
do {
    generate_secure_random_data(k, sizeof(k));
} while (!p256_sign(signature_r, signature_s, hash, sizeof(hash), privkey, k));
```

#### ECDSA Verify

In this example, SHA-256 is used as hash algorithm.

```C
// Input values
uint8_t message[] = ...;
size_t message_len = ...;
uint32_t pubkey_x[8] = ..., pubkey_y[8] = ...;
uint32_t signature_r[8] = ..., signature_s[8] = ...;

uint8_t hash[32];
sha256_hash(message, message_len, hash);

if (p256_verify(pubkey_x, pubkey_y, hash, sizeof(hash), signature_r, signature_s)) {
    // Signature is valid
} else {
    // Signature is invalid
}
```

#### ECDH Shared secret

After both parties have generated their key pair and exchanged their public keys, the shared secret can be generated. Both parties execute the following code.

```C
// Input values
uint32_t others_public_key_x[8] = ..., others_public_key_y[8] = ...; // Received from remote party
uint32_t my_private_key[8] = ...; // Generated locally earlier during keygen

// Output value
uint8_t shared_secret[32];

if (!p256_ecdh_calc_shared_secret(shared_secret, my_private_key, others_public_key_x, others_public_key_y)) {
    // The other part sent an invalid public key, so abort and take actions
    // The shared_secret will at this point contain an undefined value, and should hence not be read
} else {
    // The shared_secret is now the same for both parts and may be used for cryptographic purposes
}
```

#### Endianness conversion

If you are receiving or sending 32-byte long `uint8_t` arrays representing 256-bit integers in big-endian byte order, you may convert them to or from `uint32_t` arrays in little-endian byte order (which are commonly used in this library) using `p256_convert_endianness`.

For example, before validating a signature, call:

```C
// Input values
uint8_t signature_r_in[32] = ..., signature_s_in[32] = ...;

// Output values
uint32_t signature_r[8], signature_s[8];

p256_convert_endianness(signature_r, signature_r_in, 32);
p256_convert_endianness(signature_s, signature_s_in, 32);
```

After generating a signature, call:

```C
// Input values
uint32_t signature_r[8] = ..., signature_s[8] = ...; // from p256_sign

// Output values
uint8_t signature_r_out[32], signature_s_out[32];

p256_convert_endianness(signature_r_out, signature_r, 32);
p256_convert_endianness(signature_s_out, signature_s, 32);
```

The same technique can be used for public keys.

### Testing

The library has been tested against test vectors from Project Wycheproof (https://github.com/google/wycheproof). To run the tests, first execute `node testgen.js > tests.c` using Node >= 10.4. Then add the project files according to "How to use" plus `tests.c` and `nrf52_tests_main.c` to a new clean nRF52840 project using e.g. Segger Embedded Studio or Keil µVision. Compile and run and make sure all tests pass, by verifying that `main` returns 0.

Currently the work has been tested successfully on nRF52840, nRF5340 and MAX32670.

### Performance
The following numbers were obtained on a nRF52840 with ICACHE turned on, using GCC as compiler with `-O2` optimization.

Operation | Cycles | Time at 64 MHz
--- | --- | ---
Key generation ECDH/ECDSA | 327k | 5.1 ms
Sign ECDSA | 375k | 5.9 ms
Verify ECDSA | 976k | 15.3 ms
Shared secret ECDH | 906k | 14.2 ms
Point decompression | 48k | 0.75 ms

With all features enabled, the full library takes 8.9 kB in compiled form. 1.5 kB can be saved by enabling options that trades code space for performance.

The stack usage is at most 2 kB.

### Security
The implementation runs in constant time (unless input values are invalid) and uses a constant code memory access pattern, regardless of the scalar/private key in order to protect against side channel attacks. If desired, in particular when the processor has a data cache (like Cortex-A processors), the `has_d_cache` option can be enabled which also causes the RAM access pattern to be constant, at the expense of ~10% performance decrease.

### Code
The code is written in Keil's assembler format but was converted to GCC's assembler syntax using the included script `convert-keil-to-gcc.sh` (reads from stdin and writes to stdout).

### Copying
The code is licensed under the MIT license.

### Thanks
Thanks to ASSA ABLOY PPI for funding this work!

https://github.com/assaabloy-ppi

https://assaabloy.com
