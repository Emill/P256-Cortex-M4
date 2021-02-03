	.syntax unified
	.thumb
// Copyright (c) 2017-2021 Emil Lenngren
// Copyright (c) 2021 Shortcut Labs AB
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// P256-Cortex-M4

#include "p256-cortex-m4-config.h"

// This is an armv7 implementation of P-256.
//
// When secret data is processed, the implementation runs in constant time,
// and no conditional branches depend on secret data.

	.text
	.align 2

#if (include_p256_basemult || include_p256_varmult) && has_d_cache
// Selects one of many values
// *r0 = output, *r1 = table, r2 = num coordinates, r3 = index to choose [0..7]
// 547 cycles for affine coordinates
	.type P256_select_point, %function
P256_select_point:
	.global P256_select_point
	push {r0,r2,r3,r4-r11,lr}
	//frame push {r4-r11,lr}
	//frame address sp,48
	
	subs r2,#1
	lsls r2,#5

0:
	rsbs r3,#0
	sbcs r3,r3,r3
	mvns r3,r3
	
	ldm r1!,{r6-r12,lr}
	ands r6,r3
	ands r7,r3
	and r8,r3
	and r9,r3
	and r10,r3
	and r11,r3
	and r12,r3
	and lr,r3
	
	adds r1,r2
	
	movs r3,#1
1:
	ldr r0,[sp,#8]
	eors r0,r3
	mrs r0,apsr
	lsrs r0,#30
	
	ldm r1!,{r4,r5}
	umlal r6,r2,r0,r4
	umlal r7,r3,r0,r5
	ldm r1!,{r4,r5}
	umlal r8,r2,r0,r4
	umlal r9,r3,r0,r5
	ldm r1!,{r4,r5}
	umlal r10,r2,r0,r4
	umlal r11,r3,r0,r5
	ldm r1!,{r4,r5}
	umlal r12,r2,r0,r4
	umlal lr,r3,r0,r5
	
	adds r1,r2
	adds r3,#1
	cmp r3,#8
	bne 1b
	
	ldm sp,{r0,r4}
	stm r0!,{r6-r12,lr}
	str r0,[sp]
	
	sub r1,r1,r2, lsl #3
	subs r1,#224
	
	subs r4,#1
	str r4,[sp,#4]
	ldr r3,[sp,#8]
	bne 0b
	
	add sp,#12
	//frame address sp,36
	pop {r4-r11,pc}
	.size P256_select_point, .-P256_select_point
#endif
	
#if include_p256_verify || include_p256_sign
// in: *r0 = out, *r1 = a, *r2 = b
// quite slow, so only used in code not critical for performance
	.type mul288x288, %function
mul288x288:
	push {r4-r11,lr}
	//frame push {r4-r11,lr}
	
	mov r4,r0
	mov r5,r2
	mov r6,r1
	
	movs r1,#72
	bl setzero
	
	ldm r5,{r0-r2,r8-r12,lr}

	movs r7,#9
0:
	ldm r6!,{r5}
	push {r6,r7}
	//frame address sp,44
	movs r3,#0
	ldm r4,{r6,r7}
	umaal r6,r3,r5,r0
	umaal r7,r3,r5,r1
	stm r4!,{r6,r7}
	ldm r4,{r6,r7}
	umaal r6,r3,r5,r2
	umaal r7,r3,r5,r8
	stm r4!,{r6,r7}
	ldm r4,{r6,r7}
	umaal r6,r3,r5,r9
	umaal r7,r3,r5,r10
	stm r4!,{r6,r7}
	ldm r4,{r6,r7}
	umaal r6,r3,r5,r11
	umaal r7,r3,r5,r12
	stm r4!,{r6,r7}
	ldm r4,{r6}
	umaal r3,r6,r5,lr
	stm r4!,{r3,r6}
	
	subs r4,r4,#36
	pop {r6,r7}
	//frame address sp,36
	subs r7,r7,#1
	bne 0b
	
	pop {r4-r11,pc}
	.size mul288x288, .-mul288x288
// in: r0 = address, r1 = num bytes (> 0, must be multiple of 8)
	.type setzero, %function
setzero:
	movs r2,#0
	movs r3,#0
0:
	stm r0!,{r2,r3}
	subs r1,r1,#8
	bne 0b
	bx lr
	.size setzero, .-setzero
#endif
	
	
// Field arithmetics for the prime field where p = 2^256 - 2^224 + 2^192 + 2^96 - 1
// Multiplication and Squaring use Montgomery Modular Multiplication where R = 2^256
// To convert a value to Montgomery class, use P256_mulmod(value, R^512 mod p)
// To convert a value from Montgomery class to standard form, use P256_mulmod(value, 1)

#if include_p256_mult || include_p256_decompress_point || include_p256_decode_point
#if use_mul_for_sqr
	.type P256_sqrmod, %function
P256_sqrmod:
	push {r0-r7,lr}
	//frame push {lr}
	//frame address sp,36
	mov r1,sp
	mov r2,sp
	bl P256_mulmod
	add sp,sp,#32
	//frame address sp,4
	pop {pc}
	.size P256_sqrmod, .-P256_sqrmod
#endif
	
#if has_fpu
// If inputs are A*R mod p and B*R mod p, computes AB*R mod p
// *r1 = in1, *r2 = in2
// out: r0-r7
// clobbers all other registers
	.type P256_mulmod, %function
P256_mulmod:
	push {lr}
	//frame push {lr}
	
	vmov s4,r2
	vldm r1,{s8-s15}
	
	ldm r2,{r2,r3,r4,r5}
	
	vmov r0,r10,s8,s9
	umull r6,r1,r2,r0
	
	umull r7,r12,r3,r0
	umaal r7,r1,r2,r10
	
	vmov s0,s1,r6,r7
	
	umull r8,r6,r4,r0
	umaal r8,r1,r3,r10
	
	umull r9,r7,r5,r0
	umaal r9,r1,r4,r10
	
	umaal r1,r7,r5,r10
	
	vmov lr,r0,s10,s11
	
	umaal r8,r12,r2,lr
	umaal r9,r12,r3,lr
	umaal r1,r12,r4,lr
	umaal r12,r7,r5,lr
	
	umaal r9,r6,r2,r0
	umaal r1,r6,r3,r0
	umaal r12,r6,r4,r0
	umaal r6,r7,r5,r0
	
	vmov s2,s3,r8,r9
	
	vmov r10,lr,s12,s13
	
	mov r9,#0
	umaal r1,r9,r2,r10
	umaal r12,r9,r3,r10
	umaal r6,r9,r4,r10
	umaal r7,r9,r5,r10
	
	mov r10,#0
	umaal r12,r10,r2,lr
	umaal r6,r10,r3,lr
	umaal r7,r10,r4,lr
	umaal r9,r10,r5,lr
	
	vmov r8,s14
	mov lr,#0
	umaal lr,r6,r2,r8
	umaal r7,r6,r3,r8
	umaal r9,r6,r4,r8
	umaal r10,r6,r5,r8
	
	//_ _ _ _ _ 6 10 9| 7 | lr 12 1 _ _ _ _
	
	vmov r8,s15
	mov r11,#0
	umaal r7,r11,r2,r8
	umaal r9,r11,r3,r8
	umaal r10,r11,r4,r8
	umaal r6,r11,r5,r8
	
	//_ _ _ _ 11 6 10 9| 7 | lr 12 1 _ _ _ _
	
	vmov r2,s4
	adds r2,r2,#16
	ldm r2,{r2,r3,r4,r5}
	
	vmov r8,s8
	movs r0,#0
	umaal r1,r0,r2,r8
	vmov s4,r1
	umaal r12,r0,r3,r8
	umaal lr,r0,r4,r8
	umaal r0,r7,r5,r8 // 7=carry for 9
	
	//_ _ _ _ 11 6 10 9+7| 0 | lr 12 _ _ _ _ _
	
	vmov r8,s9
	movs r1,#0
	umaal r12,r1,r2,r8
	vmov s5,r12
	umaal lr,r1,r3,r8
	umaal r0,r1,r4,r8
	umaal r1,r7,r5,r8 // 7=carry for 10
	
	//_ _ _ _ 11 6 10+7 9+1| 0 | lr _ _ _ _ _ _
	
	vmov r8,s10
	mov r12,#0
	umaal lr,r12,r2,r8
	vmov s6,lr
	umaal r0,r12,r3,r8
	umaal r1,r12,r4,r8
	umaal r10,r12,r5,r8 // 12=carry for 6
	
	//_ _ _ _ 11 6+12 10+7 9+1| 0 | _ _ _ _ _ _ _
	
	vmov r8,s11
	mov lr,#0
	umaal r0,lr,r2,r8
	vmov s7,r0
	umaal r1,lr,r3,r8
	umaal r10,lr,r4,r8
	umaal r6,lr,r5,r8 // lr=carry for saved
	
	//_ _ _ _ 11+lr 6+12 10+7 9+1| _ | _ _ _ _ _ _ _
	
	vmov r0,r8,s12,s13
	umaal r1,r9,r2,r0
	vmov s8,r1
	umaal r9,r10,r3,r0
	umaal r10,r6,r4,r0
	umaal r11,r6,r5,r0 // 6=carry for next
	
	//_ _ _ 6 11+lr 10+12 9+7 _ | _ | _ _ _ _ _ _ _
	
	umaal r9,r7,r2,r8
	umaal r10,r7,r3,r8
	umaal r11,r7,r4,r8
	umaal r6,r7,r5,r8
	
	vmov r0,r8,s14,s15
	umaal r10,r12,r2,r0
	umaal r11,r12,r3,r0
	umaal r6,r12,r4,r0
	umaal r7,r12,r5,r0
	
	umaal r11,lr,r2,r8
	umaal lr,r6,r3,r8
	umaal r6,r7,r4,r8
	umaal r7,r12,r5,r8
	
	// 12 7 6 lr 11 10 9 s8 s7 s6 s5 s4 s3 s2 s1 s0
	
	//now reduce
	vmov s13,s14,r6,r7
	vmov s15,r12
	
	vmov r0,r1,s0,s1
	vmov r2,r3,s2,s3
	vmov r4,r5,s4,s5
	vmov r6,r7,s6,s7
	vmov r8,s8
	
	mov r12,#0

	adds r3,r0
	adcs r4,r4,r1
	adcs r5,r5,r2
	adcs r6,r6,r0
	adcs r7,r7,r1
	adcs r8,r8,r0
	adcs r9,r9,r1
	adcs r10,r10,#0
	adcs r11,r11,#0
	adcs r12,r12,#0

	adds r6,r3
	adcs r7,r7,r4 // r4 instead of 0
	adcs r8,r8,r2
	adcs r9,r9,r3
	adcs r10,r10,r2
	adcs r11,r11,r3
	adcs r12,r12,#0

	subs r7,r0
	sbcs r8,r8,r1
	sbcs r9,r9,r2
	sbcs r10,r10,r3
	sbcs r11,r11,#0
	sbcs r12,r12,#0 // r12 is between 0 and 2

	vmov r1,r2,s13,s14
	vmov r3,s15

	adds r0,lr,r12
	adcs r1,r1,#0
	mov r12,#0
	adcs r12,r12,#0

	//adds r7,r4 (added above instead)
	adcs r8,r8,r5
	adcs r9,r9,r6
	adcs r10,r10,r4
	adcs r11,r11,r5
	adcs r0,r0,r4
	adcs r1,r1,r5
	adcs r2,r2,r12
	adcs r3,r3,#0
	mov r12,#0
	adcs r12,r12,#0

	adcs r10,r10,r7
	adcs r11,r11,#0
	adcs r0,r0,r6
	adcs r1,r1,r7
	adcs r2,r2,r6
	adcs r3,r3,r7
	adcs r12,r12,#0

	subs r11,r4
	sbcs r0,r0,r5
	sbcs r1,r1,r6
	sbcs r2,r2,r7
	sbcs r3,r3,#0
	sbcs r12,r12,#0
	
	// now (T + mN) / R is
	// 8 9 10 11 0 1 2 3 12 (lsb -> msb)
	
	subs r8,r8,#0xffffffff
	sbcs r9,r9,#0xffffffff
	sbcs r10,r10,#0xffffffff
	sbcs r11,r11,#0
	sbcs r4,r0,#0
	sbcs r5,r1,#0
	sbcs r6,r2,#1
	sbcs r7,r3,#0xffffffff
	sbc r12,r12,#0
	
	adds r0,r8,r12
	adcs r1,r9,r12
	adcs r2,r10,r12
	adcs r3,r11,#0
	adcs r4,r4,#0
	adcs r5,r5,#0
	adcs r6,r6,r12, lsr #31
	adcs r7,r7,r12
	
	pop {pc}
	.size P256_mulmod, .-P256_mulmod
	
#if !use_mul_for_sqr
// If input is A*R mod p, computes A^2*R mod p
// in/out: r0-r7
// clobbers all other registers
	.type P256_sqrmod, %function
P256_sqrmod:
	push {lr}
	//frame push {lr}
	
	//mul 01, 00
	umull r9,r10,r0,r0
	umull r11,r12,r0,r1
	adds r11,r11,r11
	mov lr,#0
	umaal r10,r11,lr,lr
	
	//r9 r10 done
	//r12 carry for 3rd before col
	//r11+C carry for 3rd final col
	
	vmov s0,s1,r9,r10
	
	//mul 02, 11
	mov r8,#0
	umaal r8,r12,r0,r2
	adcs r8,r8,r8
	umaal r8,r11,r1,r1
	
	//r8 done (3rd col)
	//r12 carry for 4th before col
	//r11+C carry for 4th final col
	
	//mul 03, 12
	umull r9,r10,r0,r3
	umaal r9,r12,r1,r2
	adcs r9,r9,r9
	umaal r9,r11,lr,lr
	
	//r9 done (4th col)
	//r10+r12 carry for 5th before col
	//r11+C carry for 5th final col
	
	vmov s2,s3,r8,r9
	
	//mul 04, 13, 22
	mov r9,#0
	umaal r9,r10,r0,r4
	umaal r9,r12,r1,r3
	adcs r9,r9,r9
	umaal r9,r11,r2,r2
	
	//r9 done (5th col)
	//r10+r12 carry for 6th before col
	//r11+C carry for 6th final col
	
	vmov s4,r9
	
	//mul 05, 14, 23
	umull r9,r8,r0,r5
	umaal r9,r10,r1,r4
	umaal r9,r12,r2,r3
	adcs r9,r9,r9
	umaal r9,r11,lr,lr
	
	//r9 done (6th col)
	//r10+r12+r8 carry for 7th before col
	//r11+C carry for 7th final col
	
	vmov s5,r9
	
	//mul 06, 15, 24, 33
	mov r9,#0
	umaal r9,r8,r1,r5
	umaal r9,r12,r2,r4
	umaal r9,r10,r0,r6
	adcs r9,r9,r9
	umaal r9,r11,r3,r3
	
	//r9 done (7th col)
	//r8+r10+r12 carry for 8th before col
	//r11+C carry for 8th final col
	
	vmov s6,r9
	
	//mul 07, 16, 25, 34
	umull r0,r9,r0,r7
	umaal r0,r10,r1,r6
	umaal r0,r12,r2,r5
	umaal r0,r8,r3,r4
	adcs r0,r0,r0
	umaal r0,r11,lr,lr
	
	//r0 done (8th col)
	//r9+r8+r10+r12 carry for 9th before col
	//r11+C carry for 9th final col
	
	//mul 17, 26, 35, 44
	umaal r9,r8,r1,r7 //r1 is now dead
	umaal r9,r10,r2,r6
	umaal r12,r9,r3,r5
	adcs r12,r12,r12
	umaal r11,r12,r4,r4
	
	//r11 done (9th col)
	//r8+r10+r9 carry for 10th before col
	//r12+C carry for 10th final col
	
	//mul 27, 36, 45
	umaal r9,r8,r2,r7 //r2 is now dead
	umaal r10,r9,r3,r6
	movs r2,#0
	umaal r10,r2,r4,r5
	adcs r10,r10,r10
	umaal r12,r10,lr,lr
	
	//r12 done (10th col)
	//r8+r9+r2 carry for 11th before col
	//r10+C carry for 11th final col
	
	//mul 37, 46, 55
	umaal r2,r8,r3,r7 //r3 is now dead
	umaal r9,r2,r4,r6
	adcs r9,r9,r9
	umaal r10,r9,r5,r5
	
	//r10 done (11th col)
	//r8+r2 carry for 12th before col
	//r9+C carry for 12th final col
	
	//mul 47, 56
	movs r3,#0
	umaal r3,r8,r4,r7 //r4 is now dead
	umaal r3,r2,r5,r6
	adcs r3,r3,r3
	umaal r9,r3,lr,lr
	
	//r9 done (12th col)
	//r8+r2 carry for 13th before col
	//r3+C carry for 13th final col
	
	//mul 57, 66
	umaal r8,r2,r5,r7 //r5 is now dead
	adcs r8,r8,r8
	umaal r3,r8,r6,r6
	
	//r3 done (13th col)
	//r2 carry for 14th before col
	//r8+C carry for 14th final col
	
	//mul 67
	umull r4,r5,lr,lr // set 0
	umaal r4,r2,r6,r7
	adcs r4,r4,r4
	umaal r4,r8,lr,lr
	
	//r4 done (14th col)
	//r2 carry for 15th before col
	//r8+C carry for 15th final col
	
	//mul 77
	adcs r2,r2,r2
	umaal r8,r2,r7,r7
	adcs r2,r2,lr
	
	//r8 done (15th col)
	//r2 done (16th col)
	
	//msb -> lsb: r2 r8 r4 r3 r9 r10 r12 r11 r0 s6 s5 s4 s3 s2 s1 s0
	//lr: 0
	//now do reduction
	
	vmov s13,s14,r4,r8
	vmov s15,r2 //s15
	
	vmov r1,r2,s0,s1
	vmov r8,r7,s2,s3
	vmov r6,r5,s4,s5
	vmov r4,s6
	//lr is already 0
	X0 .req r1
	X1 .req r2
	X2 .req r8
	X3 .req r7
	X4 .req r6
	X5 .req r5
	X6 .req r4
	X7 .req r0
	X8 .req r11
	X9 .req r12
	X10 .req r10
	X11 .req r9
	X12 .req r3

	X13 .req r7
	X14 .req r8
	X15 .req r2

	adcs X3,X3,X0
	adcs X4,X4,X1
	adcs X5,X5,X2
	adcs X6,X6,X0
	adcs X7,X7,X1
	adcs X8,X8,X0
	adcs X9,X9,X1
	adcs X10,X10,#0
	adcs X11,X11,#0
	adcs lr,lr,#0

	adds X6,X3
	adcs X7,X7,X4 // X4 instead of 0
	adcs X8,X8,X2
	adcs X9,X9,X3
	adcs X10,X10,X2
	adcs X11,X11,X3
	adcs lr,lr,#0

	subs X7,X0
	sbcs X8,X8,X1
	sbcs X9,X9,X2
	sbcs X10,X10,X3
	sbcs X11,X11,#0
	sbcs lr,lr,#0 // lr is between 0 and 2
	
	vmov X13,X14,s13,s14
	vmov X15,s15

	adds X0,X12,lr
	adcs X13,X13,#0
	mov lr,#0
	adcs lr,lr,#0

	//adds X7,X4 (added above instead)
	adcs X8,X8,X5
	adcs X9,X9,X6
	adcs X10,X10,X4
	adcs X11,X11,X5
	adcs X0,X0,X4
	adcs X13,X13,X5
	adcs X14,X14,lr
	adcs X15,X15,#0
	mov lr,#0
	adcs lr,lr,#0

	adcs X10,X10,X7
	adcs X11,X11,#0
	adcs X0,X0,X6
	adcs X13,X13,X7
	adcs X14,X14,X6
	adcs X15,X15,X7
	adcs lr,lr,#0

	subs X11,X4
	sbcs X0,X0,X5
	sbcs X13,X13,X6
	sbcs X14,X14,X7
	sbcs X15,X15,#0
	sbcs lr,lr,#0
	
	// now (T + mN) / R is
	// X8 X9 X10 X11 X0 X13 X14 X15 lr (lsb -> msb)
	// r11 r12 r10 r9 r1 r7 r8 r2 lr
	
	subs r0,r11,#0xffffffff
	sbcs r12,r12,#0xffffffff
	sbcs r4,r10,#0xffffffff
	sbcs r9,r9,#0
	sbcs r6,r1,#0
	sbcs r5,r7,#0
	sbcs r10,r8,#1
	sbcs r8,r2,#0xffffffff
	sbcs r7,lr,#0
	
	adds r0,r0,r7
	adcs r1,r12,r7
	adcs r2,r4,r7
	adcs r3,r9,#0
	adcs r4,r6,#0
	adcs r5,r5,#0
	adcs r6,r10,r7, lsr #31
	adcs r7,r8,r7
	
	pop {pc}
	.size P256_sqrmod, .-P256_sqrmod
#endif
	
#else
// If inputs are A*R mod p and B*R mod p, computes AB*R mod p
// *r1 = in1, *r2 = in2
// out: r0-r7
// clobbers all other registers
// cycles: 231
	.type P256_mulmod, %function
P256_mulmod:
	push {r2,lr}
	//frame push {lr}
	//frame address sp,8
	
	sub sp,#28
	//frame address sp,36
	ldm r2,{r2,r3,r4,r5}
	
	ldm r1!,{r0,r10,lr}
	umull r6,r11,r2,r0
	
	umull r7,r12,r3,r0
	umaal r7,r11,r2,r10
	
	push {r6,r7}
	//frame address sp,44
	
	umull r8,r6,r4,r0
	umaal r8,r11,r3,r10
	
	umull r9,r7,r5,r0
	umaal r9,r11,r4,r10
	
	umaal r11,r7,r5,r10
	
	umaal r8,r12,r2,lr
	umaal r9,r12,r3,lr
	umaal r11,r12,r4,lr
	umaal r12,r7,r5,lr
	
	ldm r1!,{r0,r10,lr}
	
	umaal r9,r6,r2,r0
	umaal r11,r6,r3,r0
	umaal r12,r6,r4,r0
	umaal r6,r7,r5,r0
	
	strd r8,r9,[sp,#8]
	
	mov r9,#0
	umaal r11,r9,r2,r10
	umaal r12,r9,r3,r10
	umaal r6,r9,r4,r10
	umaal r7,r9,r5,r10
	
	mov r10,#0
	umaal r12,r10,r2,lr
	umaal r6,r10,r3,lr
	umaal r7,r10,r4,lr
	umaal r9,r10,r5,lr
	
	ldr r8,[r1],#4
	mov lr,#0
	umaal lr,r6,r2,r8
	umaal r7,r6,r3,r8
	umaal r9,r6,r4,r8
	umaal r10,r6,r5,r8
	
	//_ _ _ _ _ 6 10 9| 7 | lr 12 11 _ _ _ _
	
	ldr r8,[r1],#-28
	mov r0,#0
	umaal r7,r0,r2,r8
	umaal r9,r0,r3,r8
	umaal r10,r0,r4,r8
	umaal r6,r0,r5,r8
	
	push {r0}
	//frame address sp,48
	
	//_ _ _ _ s 6 10 9| 7 | lr 12 11 _ _ _ _
	
	ldr r2,[sp,#40]
	adds r2,r2,#16
	ldm r2,{r2,r3,r4,r5}
	
	ldr r8,[r1],#4
	mov r0,#0
	umaal r11,r0,r2,r8
	str r11,[sp,#16+4]
	umaal r12,r0,r3,r8
	umaal lr,r0,r4,r8
	umaal r0,r7,r5,r8 // 7=carry for 9
	
	//_ _ _ _ s 6 10 9+7| 0 | lr 12 _ _ _ _ _
	
	ldr r8,[r1],#4
	mov r11,#0
	umaal r12,r11,r2,r8
	str r12,[sp,#20+4]
	umaal lr,r11,r3,r8
	umaal r0,r11,r4,r8
	umaal r11,r7,r5,r8 // 7=carry for 10
	
	//_ _ _ _ s 6 10+7 9+11| 0 | lr _ _ _ _ _ _
	
	ldr r8,[r1],#4
	mov r12,#0
	umaal lr,r12,r2,r8
	str lr,[sp,#24+4]
	umaal r0,r12,r3,r8
	umaal r11,r12,r4,r8
	umaal r10,r12,r5,r8 // 12=carry for 6
	
	//_ _ _ _ s 6+12 10+7 9+11| 0 | _ _ _ _ _ _ _
	
	ldr r8,[r1],#4
	mov lr,#0
	umaal r0,lr,r2,r8
	str r0,[sp,#28+4]
	umaal r11,lr,r3,r8
	umaal r10,lr,r4,r8
	umaal r6,lr,r5,r8 // lr=carry for saved
	
	//_ _ _ _ s+lr 6+12 10+7 9+11| _ | _ _ _ _ _ _ _
	
	ldm r1!,{r0,r8}
	umaal r11,r9,r2,r0
	str r11,[sp,#32+4]
	umaal r9,r10,r3,r0
	umaal r10,r6,r4,r0
	pop {r11}
	//frame address sp,44
	umaal r11,r6,r5,r0 // 6=carry for next
	
	//_ _ _ 6 11+lr 10+12 9+7 _ | _ | _ _ _ _ _ _ _
	
	umaal r9,r7,r2,r8
	umaal r10,r7,r3,r8
	umaal r11,r7,r4,r8
	umaal r6,r7,r5,r8
	
	ldm r1!,{r0,r8}
	umaal r10,r12,r2,r0
	umaal r11,r12,r3,r0
	umaal r6,r12,r4,r0
	umaal r7,r12,r5,r0
	
	umaal r11,lr,r2,r8
	umaal lr,r6,r3,r8
	umaal r6,r7,r4,r8
	umaal r7,r12,r5,r8
	
	// 12 7 6 lr 11 10 9 stack*9
	push {r6,r7,r12}
	//frame address sp,56
	add r7,sp,#12
	ldm r7,{r0-r8}
	
	mov r12,#0

	adds r3,r0
	adcs r4,r4,r1
	adcs r5,r5,r2
	adcs r6,r6,r0
	adcs r7,r7,r1
	adcs r8,r8,r0
	adcs r9,r9,r1
	adcs r10,r10,#0
	adcs r11,r11,#0
	adcs r12,r12,#0

	adds r6,r3
	adcs r7,r7,r4 // r4 instead of 0
	adcs r8,r8,r2
	adcs r9,r9,r3
	adcs r10,r10,r2
	adcs r11,r11,r3
	adcs r12,r12,#0

	subs r7,r0
	sbcs r8,r8,r1
	sbcs r9,r9,r2
	sbcs r10,r10,r3
	sbcs r11,r11,#0
	sbcs r12,r12,#0 // r12 is between 0 and 2

	pop {r1-r3}
	//frame address sp,44

	adds r0,lr,r12
	adcs r1,r1,#0
	mov r12,#0
	adcs r12,r12,#0

	//adds r7,r4 (added above instead)
	adcs r8,r8,r5
	adcs r9,r9,r6
	adcs r10,r10,r4
	adcs r11,r11,r5
	adcs r0,r0,r4
	adcs r1,r1,r5
	adcs r2,r2,r12
	adcs r3,r3,#0
	mov r12,#0
	adcs r12,r12,#0

	adcs r10,r10,r7
	adcs r11,r11,#0
	adcs r0,r0,r6
	adcs r1,r1,r7
	adcs r2,r2,r6
	adcs r3,r3,r7
	adcs r12,r12,#0

	subs r11,r4
	sbcs r0,r0,r5
	sbcs r1,r1,r6
	sbcs r2,r2,r7
	sbcs r3,r3,#0
	sbcs r12,r12,#0
	
	// now (T + mN) / R is
	// 8 9 10 11 0 1 2 3 12 (lsb -> msb)
	
	subs r8,r8,#0xffffffff
	sbcs r9,r9,#0xffffffff
	sbcs r10,r10,#0xffffffff
	sbcs r11,r11,#0
	sbcs r4,r0,#0
	sbcs r5,r1,#0
	sbcs r6,r2,#1
	sbcs r7,r3,#0xffffffff
	sbc r12,r12,#0
	
	adds r0,r8,r12
	adcs r1,r9,r12
	adcs r2,r10,r12
	adcs r3,r11,#0
	adcs r4,r4,#0
	adcs r5,r5,#0
	adcs r6,r6,r12, lsr #31
	adcs r7,r7,r12
	
	add sp,sp,#40
	//frame address sp,4
	
	pop {pc}
	
	.size P256_mulmod, .-P256_mulmod

#if !use_mul_for_sqr
// 173 cycles
// If input is A*R mod p, computes A^2*R mod p
// in/out: r0-r7
// clobbers all other registers
	.type P256_sqrmod, %function
P256_sqrmod:
	push {lr}
	//frame push {lr}
	
	//mul 01, 00
	umull r9,r10,r0,r0
	umull r11,r12,r0,r1
	adds r11,r11,r11
	mov lr,#0
	umaal r10,r11,lr,lr
	
	//r10 r9 done
	//r12 carry for 3rd before col
	//r11+C carry for 3rd final col
	
	push {r9,r10}
	//frame address sp,12
	
	//mul 02, 11
	mov r9,#0
	umaal r9,r12,r0,r2
	adcs r9,r9,r9
	umaal r9,r11,r1,r1
	
	//r9 done (3rd col)
	//r12 carry for 4th before col
	//r11+C carry for 4th final col
	
	push {r9}
	//frame address sp,16
	
	//mul 03, 12
	umull r9,r10,r0,r3
	umaal r9,r12,r1,r2
	adcs r9,r9,r9
	umaal r9,r11,lr,lr
	
	//r9 done (4th col)
	//r10+r12 carry for 5th before col
	//r11+C carry for 5th final col
	
	push {r9}
	//frame address sp,20
	
	//mul 04, 13, 22
	mov r9,#0
	umaal r9,r10,r0,r4
	umaal r9,r12,r1,r3
	adcs r9,r9,r9
	umaal r9,r11,r2,r2
	
	//r9 done (5th col)
	//r10+r12 carry for 6th before col
	//r11+C carry for 6th final col
	
	push {r9}
	//frame address sp,24
	
	//mul 05, 14, 23
	umull r9,r8,r0,r5
	umaal r9,r10,r1,r4
	umaal r9,r12,r2,r3
	adcs r9,r9,r9
	umaal r9,r11,lr,lr
	
	//r9 done (6th col)
	//r10+r12+r8 carry for 7th before col
	//r11+C carry for 7th final col
	
	push {r9}
	//frame address sp,28
	
	//mul 06, 15, 24, 33
	mov r9,#0
	umaal r9,r8,r1,r5
	umaal r9,r12,r2,r4
	umaal r9,r10,r0,r6
	adcs r9,r9,r9
	umaal r9,r11,r3,r3
	
	//r9 done (7th col)
	//r8+r10+r12 carry for 8th before col
	//r11+C carry for 8th final col
	
	push {r9}
	//frame address sp,32
	
	//mul 07, 16, 25, 34
	umull r9,r0,r0,r7
	umaal r9,r10,r1,r6
	umaal r9,r12,r2,r5
	umaal r9,r8,r3,r4
	adcs r9,r9,r9
	//push {r12}
	////frame address sp,36
	umaal r9,r11,lr,lr
	
	//r9 done (8th col)
	//r0+r8+r10+r12 carry for 9th before col
	//r11+C carry for 9th final col
	
	//mul 17, 26, 35, 44
	umaal r0,r8,r1,r7 //r1 is now dead
	umaal r0,r10,r2,r6
	//pop {r1}
	////frame address sp,32
	umaal r0,r12,r3,r5
	adcs r0,r0,r0
	umaal r11,r0,r4,r4
	
	//r11 done (9th col)
	//r8+r10+r12 carry for 10th before col
	//r0+C carry for 10th final col
	
	//mul 27, 36, 45
	umaal r12,r8,r2,r7 //r2 is now dead
	umaal r12,r10,r3,r6
	movs r2,#0
	umaal r12,r2,r4,r5
	adcs r1,r12,r12
	umaal r0,r1,lr,lr
	
	//r0 done (10th col)
	//r8+r10+r2 carry for 11th before col
	//r1+C carry for 11th final col
	
	//mul 37, 46, 55
	umaal r2,r8,r3,r7 //r3 is now dead
	umaal r2,r10,r4,r6
	adcs r2,r2,r2
	umaal r1,r2,r5,r5
	
	//r1 done (11th col)
	//r8+r10 carry for 12th before col
	//r2+C carry for 12th final col
	
	//mul 47, 56
	movs r3,#0
	umaal r3,r8,r4,r7 //r4 is now dead
	umaal r3,r10,r5,r6
	adcs r3,r3,r3
	umaal r2,r3,lr,lr
	
	//r2 done (12th col)
	//r8+r10 carry for 13th before col
	//r3+C carry for 13th final col
	
	//mul 57, 66
	umaal r8,r10,r5,r7 //r5 is now dead
	adcs r8,r8,r8
	umaal r3,r8,r6,r6
	
	//r3 done (13th col)
	//r10 carry for 14th before col
	//r8+C carry for 14th final col
	
	//mul 67
	umull r4,r5,lr,lr // set 0
	umaal r4,r10,r6,r7
	adcs r4,r4,r4
	umaal r4,r8,lr,lr
	
	//r4 done (14th col)
	//r10 carry for 15th before col
	//r8+C carry for 15th final col
	
	//mul 77
	adcs r10,r10,r10
	umaal r8,r10,r7,r7
	adcs r10,r10,lr
	
	//r8 done (15th col)
	//r10 done (16th col)
	
	//msb -> lsb: r10 r8 r4 r3 r2 r1 r0 r11 r9 sp sp+4 sp+8 sp+12 sp+16 sp+24 sp+20
	//now do reduction
	
	push {r4,r8,r10}
	//frame address sp,44
	add r4,sp,#12
	ldm r4,{r4-r8,r10,r12}
	//lr is already 0
	X0 .req r10
	X1 .req r12
	X2 .req r8
	X3 .req r7
	X4 .req r6
	X5 .req r5
	X6 .req r4
	X7 .req r9
	X8 .req r11
	X9 .req r0
	X10 .req r1
	X11 .req r2
	X12 .req r3

	X13 .req r7
	X14 .req r8
	X15 .req r12

	adcs X3,X3,X0
	adcs X4,X4,X1
	adcs X5,X5,X2
	adcs X6,X6,X0
	adcs X7,X7,X1
	adcs X8,X8,X0
	adcs X9,X9,X1
	adcs X10,X10,#0
	adcs X11,X11,#0
	adcs lr,lr,#0

	adds X6,X3
	adcs X7,X7,X4 // X4 instead of 0
	adcs X8,X8,X2
	adcs X9,X9,X3
	adcs X10,X10,X2
	adcs X11,X11,X3
	adcs lr,lr,#0

	subs X7,X0
	sbcs X8,X8,X1
	sbcs X9,X9,X2
	sbcs X10,X10,X3
	sbcs X11,X11,#0
	sbcs lr,lr,#0 // lr is between 0 and 2
	
	pop {X13,X14,X15}
	//frame address sp,32

	adds X0,X12,lr
	adcs X13,X13,#0
	mov lr,#0
	adcs lr,lr,#0

	//adds X7,X4 (added above instead)
	adcs X8,X8,X5
	adcs X9,X9,X6
	adcs X10,X10,X4
	adcs X11,X11,X5
	adcs X0,X0,X4
	adcs X13,X13,X5
	adcs X14,X14,lr
	adcs X15,X15,#0
	mov lr,#0
	adcs lr,lr,#0

	adcs X10,X10,X7
	adcs X11,X11,#0
	adcs X0,X0,X6
	adcs X13,X13,X7
	adcs X14,X14,X6
	adcs X15,X15,X7
	adcs lr,lr,#0

	subs X11,X4
	sbcs X0,X0,X5
	sbcs X13,X13,X6
	sbcs X14,X14,X7
	sbcs X15,X15,#0
	sbcs lr,lr,#0
	
	// now (T + mN) / R is
	// X8 X9 X10 X11 X0 X13 X14 X15 lr (lsb -> msb)
	// r11 r0 r1 r2 r10 r7 r8 r12 lr
	
	subs r11,r11,#0xffffffff
	sbcs r9,r0,#0xffffffff
	sbcs r4,r1,#0xffffffff
	sbcs r3,r2,#0
	sbcs r6,r10,#0
	sbcs r5,r7,#0
	sbcs r10,r8,#1
	sbcs r8,r12,#0xffffffff
	sbcs r7,lr,#0
	
	adds r0,r11,r7
	adcs r1,r9,r7
	adcs r2,r4,r7
	adcs r3,r3,#0
	adcs r4,r6,#0
	adcs r5,r5,#0
	adcs r6,r10,r7, lsr #31
	adcs r7,r8,r7
	
	add sp,#28
	//frame address sp,4
	pop {pc}
	
	.size P256_sqrmod, .-P256_sqrmod
#endif
#endif

// 42 cycles
// Computes A - B mod p, assumes A, B < p
// in: *r1, *r2
// out: r0-r7
// clobbers all other registers
	.type P256_submod, %function
P256_submod:
	ldm r1,{r3-r10}
	ldm r2!,{r0,r1,r11,r12}
	subs r3,r0
	sbcs r4,r4,r1
	sbcs r5,r5,r11
	sbcs r6,r6,r12
	ldm r2,{r0,r1,r11,r12}
	sbcs r7,r7,r0
	sbcs r8,r8,r1
	sbcs r9,r9,r11
	sbcs r10,r10,r12
	
	sbcs r11,r11,r11
	
	adds r0,r3,r11
	adcs r1,r4,r11
	adcs r2,r5,r11
	adcs r3,r6,#0
	adcs r4,r7,#0
	adcs r5,r8,#0
	adcs r6,r9,r11, lsr #31
	adcs r7,r10,r11
	
	bx lr
	
	.size P256_submod, .-P256_submod
#endif

#if include_p256_mult || include_p256_decompress_point
// 52 cycles
// Computes A + B mod p, assumes A, B < p
// in: *r1, *r2
// out: r0-r7
// clobbers all other registers
	.type P256_addmod, %function
P256_addmod:
	ldm r2,{r2-r9}
	ldm r1!,{r0,r10,r11,r12}
	adds r2,r0
	adcs r3,r3,r10
	adcs r4,r4,r11
	adcs r5,r5,r12
	ldm r1,{r0,r1,r11,r12}
	adcs r6,r6,r0
	adcs r7,r7,r1
	adcs r8,r8,r11
	adcs r9,r9,r12
	movs r10,#0
	adcs r10,r10,r10
	
	subs r2,#0xffffffff
	sbcs r3,r3,#0xffffffff
	sbcs r4,r4,#0xffffffff
	sbcs r5,r5,#0
	sbcs r6,r6,#0
	sbcs r7,r7,#0
	sbcs r8,r8,#1
	sbcs r9,r9,#0xffffffff
	sbcs r10,r10,#0
	
	adds r0,r2,r10
	adcs r1,r3,r10
	adcs r2,r4,r10
	adcs r3,r5,#0
	adcs r4,r6,#0
	adcs r5,r7,#0
	adcs r6,r8,r10, lsr #31
	adcs r7,r9,r10
	
	bx lr
	
	.size P256_addmod, .-P256_addmod
#endif
	
#if include_p256_mult || include_p256_decompress_point
// cycles: 19 + 181*n
	.type P256_sqrmod_many, %function
P256_sqrmod_many:
	// in: r0-r7, count: r8
	// out: r0-r7
	push {r8,lr}
	//frame push {r8,lr}
0:
	bl P256_sqrmod
	
	ldr r8,[sp,#0]
	subs r8,r8,#1
	str r8,[sp,#0]
	bne 0b
	
	pop {r8,pc}
	.size P256_sqrmod_many, .-P256_sqrmod_many

// in/out: r0-r7, r8: count, *r9: operand for final multiplication
	.type P256_sqrmod_many_and_mulmod, %function
P256_sqrmod_many_and_mulmod:
	push {r9,lr}
	//frame push {r9,lr}
	bl P256_sqrmod_many
	push {r0-r7}
	//frame address sp,40
	mov r1,sp
	ldr r2,[sp,#32]
	bl P256_mulmod
	add sp,#36
	//frame address sp,4
	pop {pc}
	.size P256_sqrmod_many_and_mulmod, .-P256_sqrmod_many_and_mulmod
	

// in: r0-r7 = value, r8 = 0 for modinv and 1 for sqrt
// out: r0-r7
// for modinv, call input a, then if a = A * R % p, then it calculates A^-1 * R % p = (a/R)^-1 * R % p = R^2 / a % p
// for sqrt, call input a, then if a = A * R % p, then it calculates sqrt(A) * R % p
	.type P256_modinv_sqrt, %function
P256_modinv_sqrt:
	push {r0-r8,lr}
	
	// t = a^2*a
	mov r8,#1
	mov r9,sp
	bl P256_sqrmod_many_and_mulmod
	push {r0-r7}
	
	// a4_2 = a2_0^(2^2)
	bl P256_sqrmod
	bl P256_sqrmod
	push {r0-r7}
	
	// a4_0 = a4_2*a2_0
	mov r1,sp
	add r2,sp,#32
	bl P256_mulmod
	add r8,sp,#32
	stm r8,{r0-r7}
	
	// a8_0 = a4_0^(2^(8-4))*a4_0
	mov r8,#8-4
	add r9,sp,#32
	bl P256_sqrmod_many_and_mulmod
	push {r0-r7}
	
	// a16_0 = a8_0^(2^(16-8))*a8_0
	mov r8,#16-8
	mov r9,sp
	bl P256_sqrmod_many_and_mulmod
	push {r0-r7}
	
	// a32_0 = a16_0^(2^(32-16))*a16_0
	mov r8,#16
	mov r9,sp
	bl P256_sqrmod_many_and_mulmod
	push {r0-r7}
	
	// t = a32_0^(2^(64-32))*a
	mov r8,#32
	add r9,sp,#5*32
	bl P256_sqrmod_many_and_mulmod
	
	ldr r8,[sp,#6*32]
	cmp r8,#0
	bne 0f
	
	// t = t^(2^(192-64))*a32_0
	mov r8,#192-64
	mov r9,sp
	bl P256_sqrmod_many_and_mulmod
	
	// t = t^(2^(224-192))*a32_0
	mov r8,#224-192
	mov r9,sp
	bl P256_sqrmod_many_and_mulmod
	
	// t = t^(2^(240-224))*a16_0
	mov r8,#240-224
	add r9,sp,#32
	bl P256_sqrmod_many_and_mulmod
	
	// t = t^(2^(248-240))*a8_0
	mov r8,#248-240
	add r9,sp,#64
	bl P256_sqrmod_many_and_mulmod
	
	// t = t^(2^(252-248))*a4_0
	mov r8,#252-248
	add r9,sp,#128
	bl P256_sqrmod_many_and_mulmod
	
	// t = t^(2^(256-252))*a4_2
	mov r8,#256-252
	add r9,sp,#96
	bl P256_sqrmod_many_and_mulmod
	stm sp,{r0-r7}
	
	// r = t*a
	mov r1,sp
	add r2,sp,#5*32
	bl P256_mulmod
	b 1f

0:
	// t = t^(2^(160-64))*a
	mov r8,#160-64
	add r9,sp,#5*32
	bl P256_sqrmod_many_and_mulmod
	
	// t = t^(2^(254-160))
	mov r8,#254-160
	bl P256_sqrmod_many
1:

	add sp,#6*32+4
	
	pop {pc}
	
	.size P256_modinv_sqrt, .-P256_modinv_sqrt
#endif

#if include_p256_mult
// 33 cycles
// in: r0-r7
	.type P256_times2, %function
P256_times2:
	adds r0,r0
	adcs r1,r1,r1
	adcs r2,r2,r2
	adcs r3,r3,r3
	adcs r4,r4,r4
	adcs r5,r5,r5
	adcs r6,r6,r6
	adcs r7,r7,r7
	mov r8,#0
	adcs r8,r8,r8
	
	subs r0,#0xffffffff
	sbcs r1,r1,#0xffffffff
	sbcs r2,r2,#0xffffffff
	sbcs r3,r3,#0
	sbcs r4,r4,#0
	sbcs r5,r5,#0
	sbcs r6,r6,#1
	sbcs r7,r7,#0xffffffff
	sbcs r8,r8,#0
	
	adds r0,r8
	adcs r1,r1,r8
	adcs r2,r2,r8
	adcs r3,r3,#0
	adcs r4,r4,#0
	adcs r5,r5,#0
	adcs r6,r6,r8, lsr #31
	adcs r7,r7,r8
	
	bx lr
	.size P256_times2, .-P256_times2
#endif

#if include_p256_verify || include_p256_varmult || include_p256_decompress_point
	.align 2
	// (2^256)^2 mod p
R2_mod_p:
	.word 3
	.word 0
	.word 0xffffffff
	.word 0xfffffffb
	.word 0xfffffffe
	.word 0xffffffff
	.word 0xfffffffd
	.word 4

// in: *r1
// out: *r0
	.type P256_to_montgomery, %function
P256_to_montgomery:
	.global P256_to_montgomery
	push {r0,r4-r11,lr}
	//frame push {r4-r11,lr}
	//frame address sp,40
	adr r2,R2_mod_p
	bl P256_mulmod
	pop {r8}
	//frame address sp,36
	stm r8,{r0-r7}
	pop {r4-r11,pc}
	.size P256_to_montgomery, .-P256_to_montgomery
#endif

#if include_p256_basemult || include_p256_varmult || include_p256_decompress_point
// in: *r1
// out: *r0
	.type P256_from_montgomery, %function
P256_from_montgomery:
	.global P256_from_montgomery
	push {r0,r4-r11,lr}
	//frame push {r4-r11,lr}
	//frame address sp,40
	movs r2,#0
	movs r3,#0
	push {r2-r3}
	//frame address sp,48
	push {r2-r3}
	//frame address sp,56
	push {r2-r3}
	//frame address sp,64
	movs r2,#1
	push {r2-r3}
	//frame address sp,72
	mov r2,sp
	bl P256_mulmod
	add sp,#32
	//frame address sp,40
	pop {r8}
	//frame address sp,36
	stm r8,{r0-r7}
	pop {r4-r11,pc}
	.size P256_from_montgomery, .-P256_from_montgomery
#endif

#if include_p256_verify || include_p256_varmult || include_p256_decompress_point || include_p256_decode_point
// Checks whether the input number is within [0,p-1]
// in: *r0
// out: r0 = 1 if ok, else 0
	.type P256_check_range_p, %function
P256_check_range_p:
	.global P256_check_range_p
	push {r4-r8,lr}
	//frame push {r4-r8,lr}
	
	ldm r0,{r1-r8}
	
	movs r0,#0xffffffff
	
	subs r1,r0
	sbcs r2,r2,r0
	sbcs r3,r3,r0
	sbcs r4,r4,#0
	sbcs r5,r5,#0
	sbcs r6,r6,#0
	sbcs r7,r7,#1
	sbcs r8,r8,r0
	
	sbcs r0,r0,r0
	lsrs r0,#31
	
	pop {r4-r8,pc}
	
	.size P256_check_range_p, .-P256_check_range_p
#endif


// Arithmetics for the group order n =
// 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

#if include_p256_verify || include_p256_sign
	.align 2
P256_order_mu:
	.word 0xeedf9bfe
	.word 0x012ffd85
	.word 0xdf1a6c21
	.word 0x43190552
	.word 0xffffffff
	.word 0xfffffffe
	.word 0xffffffff
	.word 0x0
	.word 0x1

// in: r0-r8 = value
// out: r0-r8
// returns input - n if input >= n, else input
// clobbers all other registers
	.type P256_reduce_mod_n_once, %function
P256_reduce_mod_n_once:
	push {lr}
	//frame push {lr}
	
	adr r10,P256_order
	ldm r10,{r10,r11,r12,lr}
	subs r0,r10
	sbcs r1,r1,r11
	sbcs r2,r2,r12
	sbcs r3,r3,lr
	sbcs r4,r4,#0xffffffff
	sbcs r5,r5,#0xffffffff
	sbcs r6,r6,#0
	sbcs r7,r7,#0xffffffff
	sbcs r8,r8,#0
	
	sbc r9,r9,r9 // sets r9 to -1 if input < n, else 0
	and r10,r9
	and r11,r9
	and r12,r9
	and lr,r9
	
	adds r0,r10
	adcs r1,r1,r11
	adcs r2,r2,r12
	adcs r3,r3,lr
	adcs r4,r4,r9
	adcs r5,r5,r9
	adcs r6,r6,#0
	adcs r7,r7,r9
	adcs r8,r8,#0
	
	pop {pc}
	.size P256_reduce_mod_n_once, .-P256_reduce_mod_n_once

// *r0 = out, *r1 = in
// uses Barrett Reduction
	.type P256_reduce_mod_n_64bytes, %function
P256_reduce_mod_n_64bytes:
	push {r0,r4-r11,lr}
	//frame push {r4-r11,lr}
	sub sp,sp,#108
	//frame address sp,148
	
	mov r10,r1
	
	add r0,sp,#36
	adds r1,r1,#28
	adr r2,P256_order_mu
	bl mul288x288
	
	mov r0,sp
	add r1,sp,#72
	adr r2,P256_order
	bl mul288x288
	
	ldm r10,{r0-r8}
	pop {r9-r12}
	//frame address sp,132
	subs r0,r0,r9
	sbcs r1,r1,r10
	sbcs r2,r2,r11
	sbcs r3,r3,r12
	pop {r9-r12,lr}
	//frame address sp,112
	sbcs r4,r4,r9
	sbcs r5,r5,r10
	sbcs r6,r6,r11
	sbcs r7,r7,r12
	sbcs r8,r8,lr
	
	bl P256_reduce_mod_n_once
	bl P256_reduce_mod_n_once
	add sp,sp,#72
	//frame address sp,40
	pop {r9}
	//frame address sp,36
	
	stm r9,{r0-r7}
	
	pop {r4-r11,pc}
	.size P256_reduce_mod_n_64bytes, .-P256_reduce_mod_n_64bytes
#endif

#if include_p256_sign
// in: *r0 = out, *r1 = in
	.type P256_reduce_mod_n_32bytes, %function
P256_reduce_mod_n_32bytes:
	.global P256_reduce_mod_n_32bytes
	push {r0,r4-r11,lr}
	//frame push {r4-r11,lr}
	//frame address sp,40
	ldm r1,{r0-r7}
	mov r8,#0
	bl P256_reduce_mod_n_once
	pop {r8}
	//frame address sp,36
	stm r8,{r0-r7}
	pop {r4-r11,pc}
	.size P256_reduce_mod_n_32bytes, .-P256_reduce_mod_n_32bytes


// Adds two numbers mod n, both inputs can be any 256-bit numbers
// out and in may overlap
// in: *r1, *r2
// out: *r0
	.type P256_add_mod_n, %function
P256_add_mod_n:
	.global P256_add_mod_n
	push {r0,r4-r11,lr}
	//frame push {r4-r11,lr}
	//frame address sp,40
	
	mov r12,r1
	
	ldm r2,{r4-r11}
	ldm r12!,{r0-r3}
	adds r0,r4
	adcs r1,r1,r5
	adcs r2,r2,r6
	adcs r3,r3,r7
	ldm r12,{r4-r7}
	adcs r4,r4,r8
	adcs r5,r5,r9
	adcs r6,r6,r10
	adcs r7,r7,r11
	movs r8,#0
	adcs r8,r8,r8
	
	bl P256_reduce_mod_n_once
	bl P256_reduce_mod_n_once
	pop {r8}
	//frame address sp,36
	stm r8,{r0-r7}
	
	pop {r4-r11,pc}
	
	.size P256_add_mod_n, .-P256_add_mod_n
#endif
	
#if include_p256_verify || include_p256_sign
// Multiplies two numbers in the range [0,2^256-1] mod n
// out and in may overlap
// in: *r1, *r2
// out: *r0
	.type P256_mul_mod_n, %function
P256_mul_mod_n:
	.global P256_mul_mod_n
	movs r3,#0
	push {r3-r10,lr}
	//frame push {r4-r10,lr}
	//frame address sp,36
	
	mov r4,r0
	
	ldm r1,{r1,r3,r5-r10}
	push {r1,r3,r5-r10}
	//frame address sp,68
	
	movs r1,#0
	push {r1}
	//frame address sp,72
	ldm r2,{r1,r3,r5-r10}
	push {r1,r3,r5-r10}
	//frame address sp,104
	
	sub sp,#72
	//frame address sp,176
	
	mov r0,sp
	add r1,sp,#72
	add r2,sp,#108
	bl mul288x288 // just reuse the 288x288-bit multiplier rather than also writing a 256x256
	
	mov r0,r4
	mov r1,sp
	bl P256_reduce_mod_n_64bytes
	
	add sp,#144
	//frame address sp,32
	pop {r4-r10,pc}
	
	.size P256_mul_mod_n, .-P256_mul_mod_n

#if include_p256_sign
// r0: delta (also returned)
// r1: f
// r2: g
// r3: dest
	.type P256_divsteps2_31, %function
P256_divsteps2_31:
	.global P256_divsteps2_31
	push {r3,r4-r8,lr}
	//frame push {r4-r8,lr}
	//frame address sp,28
	
	// u,v,q,r
	movs r4,#1
	movs r5,#0
	movs r6,#0
	movs r7,#1
	
	// counter
	mov lr,#31
	
0:
	subs r3,r0,#1
	lsl r12,r2,#31
	bic r3,r12,r3
	asrs r3,r3,#31 // mask
	lsr r8,r3,#31 // b
	
	// conditionally negate delta
	eors r0,r0,r3
	subs r0,r0,r3
	
	mul r12,r1,r3 // t = f * -b (= f * m)
	bics r1,r1,r3 // f &= ~m
	umlal r1,r12,r2,r8 // f += g * b
	umaal r2,r12,r2,r3 // g += t + g * -b (= g * m)
	
	mul r12,r4,r3
	bics r4,r4,r3
	umlal r4,r12,r6,r8
	umaal r6,r12,r6,r3
	
	mul r12,r5,r3
	bics r5,r5,r3
	umlal r5,r12,r7,r8
	umaal r7,r12,r7,r3
	
	ands r12,r2,#1 // g0 = g & 1
	adds r0,r0,#1 // delta += 1
	
	// g = (g + g0 * f) / 2
	mul r3,r12,r1
	adds r2,r2,r3
	lsrs r2,r2,#1 // we don't need the MSB
	
	umlal r6,r8,r12,r4 // q += g0 * u
	umlal r7,r8,r12,r5 // r += g0 * v
	
	adds r4,r4,r4 // u *= 2
	adds r5,r5,r5 // v *= 2
	
	subs lr,lr,#1
	bne 0b
	
	pop {r3}
	stm r3!,{r4-r7}
	
	pop {r4-r8,pc}
	.size P256_divsteps2_31, .-P256_divsteps2_31

// r0: a, r1: b
// *r2: f,g
// *r3: out
// cycles: 132
	.type P256_matrix_mul_fg_9, %function
P256_matrix_mul_fg_9:
	.global P256_matrix_mul_fg_9
	push {r4-r11,lr}
	//frame push {r4-r11,lr}
	
	// this function calculates (a * f + b * g) / 2^31, which shall be an integer
	
	// the range is [-2^30, 2^31], so if negative, the top 2 bits are both 1s
	// convert to absolute value and sign
	and r4,r0,r0,lsl #1
	asrs r4,r4,#31
	eors r0,r0,r4
	subs r0,r0,r4
	
	and r5,r1,r1,lsl #1
	asrs r5,r5,#31
	eors r1,r1,r5
	subs r1,r1,r5
	
	ldm r2!,{r6} // f sign
	ldr r7,[r2,#36] // g sign
	
	// compute the resulting sign, which will be negative if exactly one of g'sign and b's sign is negative
	eors r4,r4,r6 // combine f's sign and a's sign
	eors r5,r5,r7 // combine g's sign and b's sign
	eors r4,r4,r5 // mask for negating a * f before adding to b * g
	stm r3!,{r5}
	push {r1,r2,r3}
	//frame address sp,48
	
	// load f, which is stored as a signed 257-bit number (sign extended to 288 bits) and initially conditionally negated through r6
	// now conditionally negate it depending on the r4 mask
	ldm r2!,{r1,r3,r5-r11}
	eors r1,r1,r4
	eors r3,r3,r4
	eors r5,r5,r4
	eors r6,r6,r4
	eors r7,r7,r4
	eor r8,r8,r4
	eor r9,r9,r4
	eor r10,r10,r4
	
	subs r1,r1,r4
	sbcs r3,r3,r4
	sbcs r5,r5,r4
	sbcs r6,r6,r4
	sbcs r7,r7,r4
	sbcs r8,r8,r4
	sbcs r9,r9,r4
	sbcs r10,r10,r4
	// f is never 0, so we can skip last sbcs (for r11), since we know carry flag would be 0
	eor r4,r4,r11
	
	// multiply the signed 257-bit value by |a| (|a| <= 2^31), to get a signed 288-bit result
	umull r1,lr,r0,r1
	movs r2,#0
	umull r11,r12,r2,r2
	umaal r2,lr,r0,r3
	umaal r11,lr,r0,r5
	umull r3,r5,r12,r12
	umaal r3,lr,r0,r6
	umaal r5,lr,r0,r7
	umull r6,r7,r12,r12
	umaal r6,lr,r0,r8
	umaal r7,lr,r0,r9
	umaal r12,lr,r0,r10
	mla lr,r0,r4,lr
	// result: r1, r2, r11, r3, r5, r6, r7, r12, lr
	
	// add b*g (which also fits in a signed 288-bit value) and divide by 2^31 (the low 31 bits will all be zero before div)
	pop {r0,r4}
	//frame address sp,40
	adds r4,r4,#40
	ldm r4!,{r8,r9}
	mov r10,#0
	umaal r1,r10,r0,r8
	umaal r2,r10,r0,r9
	adds r1,r1,r1
	adcs r2,r2,r2
	ldm r4!,{r1,r8,r9}
	umaal r10,r11,r0,r1
	umaal r11,r3,r0,r8
	umaal r3,r5,r0,r9
	adcs r10,r10,r10
	adcs r11,r11,r11
	adcs r3,r3,r3
	ldm r4,{r1,r4,r8,r9}
	umaal r5,r6,r0,r1
	umaal r6,r7,r0,r4
	umaal r7,r12,r0,r8
	umaal r12,lr,r0,r9 // by divsteps2 invariant, lr will now be 0 since both f and g each fits in a signed 257-bit value
	adcs r5,r5,r5
	adcs r6,r6,r6
	adcs r7,r7,r7
	adcs r12,r12,r12
	sbcs lr,lr,lr // extract the sign bit and sign-extend it
	mvn lr,lr
	pop {r1}
	//frame address sp,36
	stm r1!,{r2,r10,r11}
	stm r1!,{r3,r5,r6,r7,r12,lr}
	
	pop {r4-r11,pc}
	.size P256_matrix_mul_fg_9, .-P256_matrix_mul_fg_9

// r0: a, r1: b
// *r2: x,y
// *r3: out
// cycles: 184
	.align 2
	.type P256_matrix_mul_mod_n, %function
P256_matrix_mul_mod_n:
	.global P256_matrix_mul_mod_n
	push {r4-r11,lr}
	//frame push {r4-r11,lr}
	
	// this function calculates a * x + b * y mod N (where N is the order of the P-256 curve)
	
	// the range is [-2^30, 2^31], so if negative, the top 2 bits are both 1s
	// convert to absolute value and sign
	and r4,r0,r0,lsl #1
	asrs r4,r4,#31
	eors r0,r0,r4
	subs r0,r0,r4
	
	and r5,r1,r1,lsl #1
	asrs r5,r5,#31
	eors r1,r1,r5
	subs r1,r1,r5
	
	ldm r2!,{r6} // x sign
	ldr r7,[r2,#32] // y sign
	
	// compute the resulting sign, which will be negative if exactly one of x'sign and y's sign is negative
	eors r4,r4,r6 // combine x's sign and a's sign
	eors r5,r5,r7 // combine y's sign and b's sign
	eors r4,r4,r5 // mask for negating a * x before adding to b * y
	stm r3!,{r5}
	push {r1,r2,r3}
	//frame address sp,48
	
	// load x, which is stored as an unsigned 256-bit integer and initially conditionally negated through r6
	// now conditionally negate it depending on the r4 mask
	ldm r2,{r1-r3,r5-r9}
	eors r1,r1,r4
	eors r2,r2,r4
	eors r3,r3,r4
	eors r5,r5,r4
	eors r6,r6,r4
	eors r7,r7,r4
	eor r8,r8,r4
	eor r9,r9,r4
	
	subs r1,r1,r4
	sbcs r2,r2,r4
	sbcs r3,r3,r4
	sbcs r5,r5,r4
	sbcs r6,r6,r4
	sbcs r7,r7,r4
	sbcs r8,r8,r4
	sbcs r9,r9,r4
	
	sbcs r4,r4,r4 // if the value is nonzero, r4 will now contain -1 and we will add N to make it positive
	
	lsrs lr,r4,#31
	mov r12,#0
	ldrd r10,r11,P256_order_local
	umaal r1,r12,lr,r10
	umaal r2,r12,lr,r11
	ldrd r10,r11,P256_order_local+8
	umaal r3,r12,lr,r10
	umaal r5,r12,lr,r11
	umaal r6,r12,lr,r4
	umaal r7,r12,lr,r4
	mov r10,#0
	umaal r8,r12,lr,r10
	umaal r9,r12,lr,r4
	
	// calculate a * x, the result fits in 287 bits
	umull r11,lr,r10,r10
	umull r10,lr,r0,r1
	umull r1,r12,r11,r11
	umaal r11,lr,r0,r2
	umaal r1,lr,r0,r3
	umull r2,r3,r12,r12
	umaal r2,lr,r0,r5
	umaal r3,lr,r0,r6
	umull r4,r5,r12,r12
	umaal r4,lr,r0,r7
	umaal r5,lr,r0,r8
	umaal r12,lr,r0,r9
	
	// add b*y, the result will fit in 288 bits
	pop {r0,r6}
	//frame address sp,40
	adds r6,r6,#36
	ldm r6!,{r8,r9}
	movs r7,#0
	umaal r10,r7,r0,r8
	umaal r11,r7,r0,r9
	ldm r6!,{r8,r9}
	umaal r1,r7,r0,r8
	umaal r2,r7,r0,r9
	ldm r6!,{r8,r9}
	umaal r3,r7,r0,r8
	umaal r4,r7,r0,r9
	ldm r6!,{r8,r9}
	umaal r5,r7,r0,r8
	umaal r12,r7,r0,r9
	add lr,lr,r7
	
	// reduce modulo N using montgomery redc algorithm
	ldr r0,=0xee00bc4f // montgomery multiplication factor N' (when R = 2^32), N*N' = -1 mod R
	mul r0,r10,r0 // m = ((T mod R)N') mod R
	movs r6,#0				// need 4-byte alignment on next instruction
	ldrd r8,r9,P256_order_local
	umaal r10,r6,r0,r8 // t = (T + mN) / R
	umaal r11,r6,r0,r9
	subs r11,r11,r8 // conditionally subtract by N unless we later find out the result becomes negative
	ldrd r8,r10,P256_order_local+8
	umaal r1,r6,r0,r8
	sbcs r1,r1,r9
	umaal r2,r6,r0,r10
	mov r9,#-1
	umaal r3,r6,r0,r9
	umaal r4,r6,r0,r9
	movs r7,#0
	umaal r5,r6,r0,r7
	umaal r12,r6,r0,r9
	umaal lr,r6,r7,r7
	sbcs r2,r2,r8
	sbcs r3,r3,r10
	sbcs r4,r4,r9
	sbcs r5,r5,r9
	sbcs r12,r12,r7
	sbcs lr,lr,r9
	sbcs r6,r6,r7 // if the result becomes negative, r6 becomes -1
	
	// conditionally add back N
	ldrd r0,r9,P256_order_local
	lsrs r6,r6,#31
	umaal r7,r11,r6,r0
	umaal r1,r11,r6,r9
	umaal r2,r11,r6,r8
	umaal r3,r11,r6,r10
	rsbs r0,r6,#0
	umaal r4,r11,r6,r0
	umaal r5,r11,r6,r0
	mov r8,#0
	umaal r11,r12,r6,r8
	umaal r12,lr,r6,r0
	
	pop {r6}
	//frame address sp,36
	stm r6!,{r7}
	stm r6!,{r1,r2,r3,r4,r5,r11,r12}
	
	pop {r4-r11,pc}
	
	.ltorg
	.size P256_matrix_mul_mod_n, .-P256_matrix_mul_mod_n
#else
// *r0=u
// *r1=x1
	.type mod_inv_vartime_inner_n, %function
mod_inv_vartime_inner_n:
	adr r11,P256_order
	ldm r0,{r2-r9}
	cmp r2,#1
	bne 1f

	orrs r10,r3,r4
	orrs r10,r5
	orrs r10,r6
	orrs r10,r7
	orrs r10,r8
	orrs r10,r9
	itt eq
	moveq r0,#1
	bxeq lr

1:
	tst r2,#1
	itt ne
	movne r0,#0
	bxne lr
2:
	lsrs r9,#1
	rrxs r8,r8
	rrxs r7,r7
	rrxs r6,r6
	rrxs r5,r5
	rrxs r4,r4
	rrxs r3,r3
	rrxs r2,r2
	stm r0,{r2-r9}
	ldm r1,{r3-r10}
	tst r3,#1
	beq 3f
	ldr r12,[r11,#0]
	adds r3,r12
	ldr r12,[r11,#4]
	adcs r4,r4,r12
	ldr r12,[r11,#8]
	adcs r5,r5,r12
	ldr r12,[r11,#12]
	adcs r6,r6,r12
	adcs r7,r7,#0xffffffff
	adcs r8,r8,#0xffffffff
	adcs r9,r9,#0
	adcs r10,r10,#0xffffffff
3:
	rrxs r10,r10
	rrxs r9,r9
	rrxs r8,r8
	rrxs r7,r7
	rrxs r6,r6
	rrxs r5,r5
	rrxs r4,r4
	rrx r3,r3
	stm r1,{r3-r10}
	tst r2,#1
	itt ne
	movne r0,#0
	bxne lr
	ldm r0,{r2-r9}
	b 2b
	
	.size mod_inv_vartime_inner_n, .-mod_inv_vartime_inner_n

// *r0 = result
// *r1 = input
	.type P256_mod_n_inv_vartime, %function
P256_mod_n_inv_vartime:
	.global P256_mod_n_inv_vartime
	push {r0,r4-r11,lr}
	//frame push {r4-r11,lr}
	//frame address sp,40
	sub sp,#128
	//frame address sp,168
	mov r0,sp
	
	// stack: u x1 v x2
	// init: u=*r1, v=p, x1=1, x2=0

	ldm r1,{r1-r8}
	stm r0!,{r1-r8}

	movs r1,#1
	movs r2,#0
	umull r3,r4,r2,r2
	umull r5,r6,r2,r2
	umull r7,r8,r2,r2
	mov r9,#0

	stm r0,{r1-r8}
	add r0,sp,#96
	stm r0,{r2-r9}
	adr r2,P256_order
	ldm r2,{r2-r9}
	add r0,sp,#64
	stm r0,{r2-r9}

0:
	mov r0,sp
	add r1,sp,#32
	bl mod_inv_vartime_inner_n
	cmp r0,#0
	it ne
	addne r0,sp,#32
	bne 2f

	add r0,sp,#64
	add r1,sp,#96
	bl mod_inv_vartime_inner_n
	cmp r0,#0
	it ne
	addne r0,sp,#96
	bne 2f

	ldm sp,{r0-r7}
	add lr,sp,#64
	ldm lr!,{r8-r11}
	subs r0,r8
	sbcs r1,r1,r9
	sbcs r2,r2,r10
	sbcs r3,r3,r11
	ldm lr!,{r8-r11}
	sbcs r4,r4,r8
	sbcs r5,r5,r9
	sbcs r6,r6,r10
	sbcs r7,r7,r11

	bcc 1f
	stm sp,{r0-r7}
	add r0,sp,#32
	add r1,sp,#32
	add r2,sp,#96
3:
	// submod here
	ldm r1,{r1,r3-r9}
	ldm r2!,{r10,r11,r12,lr}
	subs r1,r10
	sbcs r3,r3,r11
	sbcs r4,r4,r12
	sbcs r5,r5,lr
	ldm r2!,{r10,r11,r12,lr}
	sbcs r6,r6,r10
	sbcs r7,r7,r11
	sbcs r8,r8,r12
	sbcs r9,r9,lr
	
	sbcs r10,r10,r10
	adr r11,P256_order
	ldm r11,{r2,r11,r12,lr}
	and r2,r10
	and r11,r10
	and r12,r10
	and lr,r10
	adds r1,r2
	adcs r3,r3,r11
	adcs r4,r4,r12
	adcs r5,r5,lr
	adcs r6,r6,r10
	adcs r7,r7,r10
	adcs r8,r8,#0
	adcs r9,r9,r10
	stm r0,{r1,r3-r9}
	b 0b
1:
	movs r8,#0
	subs r0,r8,r0
	sbcs r1,r8,r1
	sbcs r2,r8,r2
	sbcs r3,r8,r3
	sbcs r4,r8,r4
	sbcs r5,r8,r5
	sbcs r6,r8,r6
	sbcs r7,r8,r7
	add r8,sp,#64
	stm r8,{r0-r7}
	add r0,sp,#96
	add r1,sp,#96
	add r2,sp,#32
	b 3b

2:
	ldm r0,{r0-r7}
	add sp,#128
	//frame address sp,40
	pop {r8}
	//frame address sp,36
	stm r8,{r0-r7}
	pop {r4-r11,pc}
	
	.size P256_mod_n_inv_vartime, .-P256_mod_n_inv_vartime
#endif
#endif

#if include_p256_mult
	.align 2
P256_order_local: // (arm clang assembler is broken for ldrd global labels defined in the same file)
	.type P256_order, %object
P256_order:
	.global P256_order
	.word 0xFC632551
	.word 0xF3B9CAC2
	.word 0xA7179E84
	.word 0xBCE6FAAD
	.word 0xFFFFFFFF
	.word 0xFFFFFFFF
	.word 0
	.word 0xFFFFFFFF
	.word 0
	.size P256_order, .-P256_order
#endif

#if include_p256_verify || include_p256_basemult || include_p256_raw_scalarmult_generic
// Checks whether the input number is within [1,n-1]
// in: *r0
// out: r0 = 1 if ok, else 0
	.type P256_check_range_n, %function
P256_check_range_n:
	.global P256_check_range_n
	push {r4-r11,lr}
	//frame push {r4-r11,lr}
	ldm r0,{r1-r8}
	orrs r0,r1,r2
	orrs r0,r3
	orrs r0,r4
	orrs r0,r5
	orrs r0,r6
	orrs r0,r7
	orrs r0,r8
	beq 0f
	
	adr r0,P256_order
	ldm r0!,{r9-r12}
	subs r1,r9
	sbcs r2,r2,r10
	sbcs r3,r3,r11
	sbcs r4,r4,r12
	ldm r0,{r0-r3}
	sbcs r5,r5,r0
	sbcs r6,r6,r1
	sbcs r7,r7,r2
	sbcs r8,r8,r3
	
	sbcs r0,r0,r0
	lsrs r0,#31
0:
	pop {r4-r11,pc}
	
	.size P256_check_range_n, .-P256_check_range_n
#endif
	

// Elliptic curve operations on the NIST curve P-256

#if include_p256_verify || include_p256_varmult || include_p256_decompress_point || include_p256_decode_point
	.align 2
b_mont:
	.word 0x29c4bddf
	.word 0xd89cdf62
	.word 0x78843090
	.word 0xacf005cd
	.word 0xf7212ed6
	.word 0xe5a220ab
	.word 0x04874834
	.word 0xdc30061d
three_mont:
	.word 0x3
	.word 0x0
	.word 0x0
	.word 0xfffffffd
	.word 0xffffffff
	.word 0xffffffff
	.word 0xfffffffc
	.word 0x2
#endif

#if include_p256_verify || include_p256_varmult || include_p256_decode_point
// Checks if a point is on curve
// in: *r0 = x, *r1 = y, in Montgomery form
// out: r0 = 1 if on curve, else 0
	.type P256_point_is_on_curve, %function
P256_point_is_on_curve:
	.global P256_point_is_on_curve
	push {r0,r4-r11,lr}
	//frame push {r4-r11,lr}
	//frame address sp,40
	
	// We verify y^2 - x(x^2 - 3) = b
	
	// y^2
	ldm r1,{r0-r7}
	bl P256_sqrmod
	push {r0-r7}
	//frame address sp,72
	
	// x^2
	ldr r0,[sp,#32]
	ldm r0,{r0-r7}
	bl P256_sqrmod
	push {r0-r7}
	//frame address sp,104
	
	// x^2 - 3
	mov r1,sp
	adr r2,three_mont
	bl P256_submod
	stm sp,{r0-r7}
	
	// x(x^2 - 3)
	ldr r1,[sp,#64]
	mov r2,sp
	bl P256_mulmod
	stm sp,{r0-r7}
	
	// y^2 - x(x^2 - 3)
	add r1,sp,#32
	mov r2,sp
	bl P256_submod
	
	// compare with b
	adr r8,b_mont
	ldm r8!,{r9-r12}
	eors r0,r9
	ittt eq
	eorseq r1,r10
	eorseq r2,r11
	eorseq r3,r12
	ldm r8,{r9-r12}
	itttt eq
	eorseq r4,r9
	eorseq r5,r10
	eorseq r6,r11
	eorseq r7,r12
	mov r0,#0
	it eq
	moveq r0,#1
	
	add sp,#68
	//frame address sp,36
	
	pop {r4-r11,pc}
	
	.size P256_point_is_on_curve, .-P256_point_is_on_curve
#endif

#if include_p256_basemult || include_p256_varmult || include_p256_decompress_point
	.align 2
P256_p:
	.word 0xffffffff
	.word 0xffffffff
	.word 0xffffffff
	.word 0
	.word 0
	.word 0
	.word 1
	.word 0xffffffff
#endif

#if include_p256_decompress_point
// in: r0 = output location for y, *r1 = x, r2 = parity bit for y
// out: r0 = 1 if ok, 0 if invalid x
	.type P256_decompress_point, %function
P256_decompress_point:
	.global P256_decompress_point
	push {r0,r2,r4-r11,lr}
	//frame push {r4-r11,lr}
	//frame address sp,44
	sub sp,#32
	//frame address sp,76
	
	mov r0,sp
	bl P256_to_montgomery
	ldm sp,{r0-r7}
	
	bl P256_sqrmod
	push {r0-r7}
	
	mov r1,sp
	adr r2,three_mont
	bl P256_submod
	stm sp,{r0-r7}
	//frame address sp,108
	
	add r1,sp,#32
	mov r2,sp
	bl P256_mulmod
	stm sp,{r0-r7}
	
	mov r1,sp
	adr r2,b_mont
	bl P256_addmod
	stm sp,{r0-r7}
	
	mov r8,#1
	bl P256_modinv_sqrt
	add r8,sp,#32
	stm r8,{r0-r7}
	
	bl P256_sqrmod
	
	pop {r8-r11}
	//frame address sp,92
	eors r8,r0
	ittt eq
	eorseq r9,r1
	eorseq r10,r2
	eorseq r11,r3
	pop {r8-r11}
	//frame address sp,76
	itttt eq
	eorseq r8,r4
	eorseq r9,r5
	eorseq r10,r6
	eorseq r11,r7
	it ne
	movne r0,#0
	bne 1f
	
	mov r0,sp
	mov r1,sp
	bl P256_from_montgomery
	
	ldr r3,[sp]
	ldrd r0,r1,[sp,#32]
	and r2,r3,#1
	eors r2,r1
	mov r1,sp
	adr r3,P256_p
	bl P256_negate_mod_m_if
	movs r0,#1
1:
	add sp,#32+8
	//frame address sp,36
	pop {r4-r11,pc}
	
	.size P256_decompress_point, .-P256_decompress_point
#endif

#if include_p256_basemult || include_p256_varmult
// *r0 = output affine montgomery x
// *r1 = output affine montgomery y
// *r2 = input jacobian montgomery
	.type P256_jacobian_to_affine, %function
P256_jacobian_to_affine:
	.global P256_jacobian_to_affine
	push {r0,r1,r2,r4-r11,lr}
	//frame push {r4-r11,lr}
	//frame address sp,48
	
	adds r2,#64
	ldm r2,{r0-r7}
	mov r8,#0
	bl P256_modinv_sqrt
	push {r0-r7}
	//frame address sp,80
	
	bl P256_sqrmod
	push {r0-r7}
	//frame address sp,112
	
	add r1,sp,#32
	mov r2,sp
	bl P256_mulmod
	add r8,sp,#32
	stm r8,{r0-r7}
	
	mov r1,sp
	ldr r2,[sp,#72]
	bl P256_mulmod
	ldr r8,[sp,#64]
	stm r8,{r0-r7}
	
	ldr r2,[sp,#72]
	add r1,sp,#32
	adds r2,r2,#32
	bl P256_mulmod
	ldr r8,[sp,#68]
	stm r8,{r0-r7}
	
	add sp,#76
	//frame address sp,36
	
	pop {r4-r11,pc}
	.size P256_jacobian_to_affine, .-P256_jacobian_to_affine
#endif
	
#if include_p256_mult
// Doubles the point in Jacobian form (integers are in Montgomery form)
// *r0 = out, *r1 = in
	.type P256_double_j, %function
P256_double_j:
	.global P256_double_j
	push {r0,r1,r4-r11,lr}
	//frame push {r4-r11,lr}
	//frame address sp,44
	
	// https://eprint.iacr.org/2014/130.pdf, algorithm 10
	
	// t1 = Z1^2
	adds r1,#64
	ldm r1,{r0-r7}
	bl P256_sqrmod
	push {r0-r7}
	//frame address sp,76
	
	// Z2 = Y1 * Z1
	ldr r1,[sp,#36]
	adds r1,#32
	add r2,r1,#32
	bl P256_mulmod
	ldr r8,[sp,#32]
	add r8,#64
	stm r8,{r0-r7}
	
	// t2 = X1 + t1
	ldr r1,[sp,#36]
	mov r2,sp
	bl P256_addmod
	push {r0-r7}
	//frame address sp,108
	
	// t1 = X1 - t1
	ldr r1,[sp,#68]
	add r2,sp,#32
	bl P256_submod
	add r8,sp,#32
	stm r8,{r0-r7}
	
	// t1 = t1 * t2
	add r1,sp,#32
	mov r2,sp
	bl P256_mulmod
	add r8,sp,#32
	stm r8,{r0-r7}
	
	// t2 = t1 / 2
	lsl r8,r0,#31
	adds r0,r0,r8, asr #31
	adcs r1,r1,r8, asr #31
	adcs r2,r2,r8, asr #31
	adcs r3,r3,#0
	adcs r4,r4,#0
	adcs r5,r5,#0
	adcs r6,r6,r8, lsr #31
	adcs r7,r7,r8, asr #31
	rrxs r7,r7
	rrxs r6,r6
	rrxs r5,r5
	rrxs r4,r4
	rrxs r3,r3
	rrxs r2,r2
	rrxs r1,r1
	rrx r0,r0
	stm sp,{r0-r7}
	
	// t1 = t1 + t2
	add r1,sp,#32
	mov r2,sp
	bl P256_addmod
	add r8,sp,#32
	stm r8,{r0-r7}
	
	// t2 = t1^2
	bl P256_sqrmod
	stm sp,{r0-r7}
	
	// Y2 = Y1^2
	ldr r0,[sp,#68]
	adds r0,#32
	ldm r0,{r0-r7}
	bl P256_sqrmod
	ldr r8,[sp,#64]
	add r8,#32
	stm r8,{r0-r7}
	
	// t3 = Y2^2
	bl P256_sqrmod
	push {r0-r7}
	//frame address sp,140
	
	// Y2 = X1 * Y2
	ldrd r0,r1,[sp,#96]
	add r2,r0,#32
	bl P256_mulmod
	ldr r8,[sp,#96]
	add r8,#32
	stm r8,{r0-r7}
	
	// X2 = 2 * Y2
	bl P256_times2
	ldr r8,[sp,#96]
	stm r8,{r0-r7}
	
	// X2 = t2 - X2
	add r1,sp,#32
	mov r2,r8
	bl P256_submod
	ldr r8,[sp,#96]
	stm r8,{r0-r7}
	
	// t2 = Y2 - X2
	mov r2,r8
	add r1,r2,#32
	bl P256_submod
	add r8,sp,#32
	stm r8,{r0-r7}
	
	// t1 = t1 * t2
	add r1,sp,#64
	add r2,sp,#32
	bl P256_mulmod
	add r8,sp,#64
	stm r8,{r0-r7}
	
	// Y2 = t1 - t3
	add r1,sp,#64
	mov r2,sp
	bl P256_submod
	ldr r8,[sp,#96]
	add r8,#32
	stm r8,{r0-r7}
	
	add sp,#104
	//frame address sp,36
	
	pop {r4-r11,pc}
	.size P256_double_j, .-P256_double_j

// sets the jacobian *r0 point to *r1
// if r2=1, then Y will be negated
// if r3=1, then Z will be set to 1
// clobbers all registers
	.type add_sub_helper, %function
add_sub_helper:
	push {lr}
	//frame push {lr}
	ldm r1!,{r5-r12}
	stm r0!,{r5-r12}
	ldm r1!,{r5-r12}
	cbz r2,0f
	// note that Y is never 0 for a valid point
	mov lr,#0
	rsbs r4,r2,#0
	subs r5,r4,r5
	sbcs r6,r4,r6
	sbcs r7,r4,r7
	sbcs r8,lr,r8
	sbcs r9,lr,r9
	sbcs r10,lr,r10
	sbcs r11,r2,r11
	sbcs r12,r4,r12
0:
	stm r0!,{r5-r12}
	cbnz r3,1f
	ldm r1,{r5-r12}
	stm r0,{r5-r12}
	b 2f
1:
	// Set Z3 to 1 in Montgomery form
	movs r4,#0
	umull r5,r10,r4,r4
	mvns r6,r4
	mvns r7,r4
	mov r8,#0xffffffff
	mov r9,#0xfffffffe
	
	stm r0,{r3-r10}
2:
	pop {pc}
	
	.size add_sub_helper, .-add_sub_helper

// Adds or subtracts points in Jacobian form (integers are in Montgomery form)
// The first operand is located in *r0, the second in *r1 (may not overlap)
// The result is stored at *r0
// r2 = 0 if add, 1 if sub
// r3 = 1 if the second point's Z point is 1 and therefore not loaded
//
// This function assumes the second operand is not the point at infinity,
// otherwise it handles all inputs.
// The first operand is treated at the point at infinity as long as its Z coordinate is 0.
	.type P256_add_sub_j, %function
P256_add_sub_j:
	.global P256_add_sub_j
	push {r0-r11,lr}
	//frame push {r4-r11,lr}
	//frame address sp,52
	
	//ldr r4,[r0,#64]
	//cbnz r4,2f
	add r4,r0,#64
	ldm r4,{r4-r11}
	orrs r4,r5
	orrs r4,r6
	orrs r4,r7
	orrs r4,r8
	orrs r4,r9
	orrs r4,r10
	orrs r4,r11
	bne 2f
	
	// First point is 0, so just set result to (-) the other point
	bl add_sub_helper
	add sp,#16
	//frame address sp,36
	pop {r4-r11,pc}
2:
	//frame address sp,52
	// Here a variant of
	// https://www.hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-3/addition/add-1998-cmo-2.op3
	// is used, but rearranged and uses less temporaries.
	// The first operand to the function is both (X3,Y3,Z3) and (X2,Y2,Z2).
	// The second operand to the function is (X1,Y1,Z1)
	
	cbnz r3,100f
	
	// Z1Z1 = Z1^2
	adds r1,#64
	ldm r1,{r0-r7}
	bl P256_sqrmod
	push {r0-r7}
	//frame address sp,84
	
	// U2 = X2*Z1Z1
	ldr r1,[sp,#32]
	mov r2,sp
	bl P256_mulmod
	ldr r8,[sp,#32]
	stm r8,{r0-r7}
	
	// t1 = Z1*Z1Z1
	ldr r1,[sp,#36]
	adds r1,#64
	mov r2,sp
	bl P256_mulmod
	stm sp,{r0-r7}
	
	// S2 = Y2*t1
	ldr r1,[sp,#32]
	adds r1,#32
	mov r2,sp
	bl P256_mulmod
	ldr r8,[sp,#32]
	add r8,#32
	stm r8,{r0-r7}
	b 101f
100:
	sub sp,#32
	//frame address sp,84
101:
	
	// Z2Z2 = Z2^2
	ldr r1,[sp,#32]
	adds r1,#64
	ldm r1,{r0-r7}
	bl P256_sqrmod
	push {r0-r7}
	//frame address sp,116
	
	// U1 = X1*Z2Z2
	ldr r1,[sp,#68]
	mov r2,sp
	bl P256_mulmod
	add r8,sp,#32
	stm r8,{r0-r7}
	
	// t2 = Z2*Z2Z2
	ldr r1,[sp,#64]
	adds r1,#64
	mov r2,sp
	bl P256_mulmod
	stm sp,{r0-r7}
	
	// S1 = Y1*t2
	ldr r1,[sp,#68]
	adds r1,#32
	mov r2,sp
	bl P256_mulmod
	stm sp,{r0-r7}
	
	
	// H = U2-U1
	ldr r1,[sp,#64]
	add r2,sp,#32
	bl P256_submod
	ldr r8,[sp,#64]
	stm r8,{r0-r7}
	
	// HH = H^2
	bl P256_sqrmod
	push {r0-r7}
	//frame address sp,148
	
	// Z3 = Z2*H
	ldr r2,[sp,#96]
	add r1,r2,#64
	bl P256_mulmod
	ldr r8,[sp,#96]
	add r8,#64
	stm r8,{r0-r7}
	
	// Z3 = Z1*Z3
	ldr r1,[sp,#108]
	cbnz r1,102f
	ldr r1,[sp,#100]
	adds r1,#64
	mov r2,r8
	bl P256_mulmod
	ldr r8,[sp,#96]
	add r8,#64
	stm r8,{r0-r7}
102:
	
	// HHH = H*HH
	ldr r1,[sp,#96]
	mov r2,sp
	bl P256_mulmod
	ldr r8,[sp,#96]
	stm r8,{r0-r7}
	
	//cbnz r0,3f
	orrs r1,r0 ////
	orrs r1,r2
	orrs r1,r3
	orrs r1,r4
	orrs r1,r5
	orrs r1,r6
	orrs r0,r1,r7
3:
	push {r0} // if r0 == 0: HHH is 0, which means the two input points have the same affine x coordinates
	//frame address sp,152
	
	// r = S2-+S1
	ldr r1,[sp,#100]
	adds r1,#32
	add r2,sp,#36
	ldr r3,[sp,#108]
	cbz r3,4f
	bl P256_addmod
	b 5f
4:
	bl P256_submod
5:
	ldr r8,[sp,#100]
	add r8,#32
	stm r8,{r0-r7}
	
	// check r == 0 && HHH == 0
	pop {r8}
	//frame address sp,148
	//cbnz r0,6f
	orrs r1,r0 ////
	orrs r1,r2
	orrs r1,r3
	orrs r1,r4
	orrs r1,r5
	orrs r1,r6
	orrs r1,r7
	orrs r1,r8
	bne 6f
	// Points should be doubled since addition formula can't handle this case
	// Since we have already overwritten the first point,
	// we must copy the second point after possibly negating it
	add sp,#96
	//frame address sp,52
	ldm sp,{r0-r3}
	bl add_sub_helper
	
	ldr r0,[sp,#0]
	mov r1,r0
	add sp,#16
	//frame address sp,36
	bl P256_double_j
	pop {r4-r11,pc}
6:
	//frame address sp,148
	
	// V = U1*HH
	add r1,sp,#64
	mov r2,sp
	bl P256_mulmod
	add r8,sp,#64
	stm r8,{r0-r7}
	
	// t3 = r^2
	ldr r0,[sp,#96]
	adds r0,#32
	ldm r0,{r0-r7}
	bl P256_sqrmod
	stm sp,{r0-r7}
	
	// t2 = S1*HHH
	add r1,sp,#32
	ldr r2,[sp,#96]
	bl P256_mulmod
	add r8,sp,#32
	stm r8,{r0-r7}
	
	// X3 = t3-HHH
	mov r1,sp
	ldr r2,[sp,#96]
	bl P256_submod
	ldr r8,[sp,#96]
	stm r8,{r0-r7}
	
	// t3 = 2*V
	add r0,sp,#64
	ldm r0,{r0-r7}
	bl P256_times2
	stm sp,{r0-r7}
	
	// X3 = X3-t3
	ldr r1,[sp,#96]
	mov r2,sp
	bl P256_submod
	ldr r8,[sp,#96]
	stm r8,{r0-r7}
	
	// t3 = V-X3
	add r1,sp,#64
	ldr r2,[sp,#96]
	bl P256_submod
	stm sp,{r0-r7}
	
	// t3 = r*t3
	ldr r1,[sp,#96]
	adds r1,#32
	mov r2,sp
	bl P256_mulmod
	stm sp,{r0-r7}
	
	// Y3 = t3-+t2
	ldr r0,[sp,#104]
	mov r1,sp
	add r2,sp,#32
	cbz r0,7f
	bl P256_addmod
	b 8f
7:
	bl P256_submod
8:
	ldr r8,[sp,#96]
	add r8,#32
	stm r8,{r0-r7}
	
	add sp,#112
	//frame address sp,36
	
	pop {r4-r11,pc}
	.size P256_add_sub_j, .-P256_add_sub_j
#endif

#if include_p256_verify
// Determines whether r = x (mod n)
// in: *r0 = r, *r1 = the result of the double scalarmult in jacobian form (Montgomery form)
// out: r0 will contain 1 if valid, else 0
	.type P256_verify_last_step, %function
P256_verify_last_step:
	.global P256_verify_last_step
	push {r0,r1,r4-r11,lr}
	//frame push {r4-r11,lr}
	//frame address sp,44
	sub sp,#32
	//frame address sp,76
	
	// Instead of doing an expensive field inversion and checking r = (X/Z^2 % p) (mod n),
	// accept the signature iff r*Z^2 % p = X OR (r+n<p AND (r+n)*Z^2 % p = X).
	// Proof that this is correct:
	//   if we use the standard approach, that would mean we check that
	//   r = (X/Z^2 % p) (mod n)
	//   which is the same as r+k*n = (X/Z^2 % p) for any integer k,
	//   but since the RHS is less than p and 2n > p, we only need to check for k=0,1
	//   which means checking r = (X/Z^2 % p) OR r+n = (X/Z^2 % p)
	//   For r = (X/Z^2 % p) we have that r < p and so we can instead check r*Z^2 % p = X
	//   For r+n = (X/Z^2 % p) we must first check that r+n < p and can then check (r+n)*Z^2 % p = X
	//
	// Note that since p-n is around sqrt(n), it is extremely unlikely that r+n<p
	//
	// Note that X and Z are in Montgomery form but not r,
	// so we must convert r to Montgomery form when it's time to do the multiplications
	
	// Calculate Z^2
	add r1,#64
	ldm r1,{r0-r7}
	bl P256_sqrmod
	push {r0-r7}
	//frame address sp,108
	
	// Check if Z^2 if 0, if so reject
	orrs r0,r1
	orrs r0,r2
	orrs r0,r3
	orrs r0,r4
	orrs r0,r5
	orrs r0,r6
	orrs r0,r7
	beq 0f
	
	// Convert r to Montgomery form
	ldr r1,[sp,#64]
2:
	add r0,sp,#32
	bl P256_to_montgomery
	
	// Calculate r*Z^2
	add r1,sp,#32
	mov r2,sp
	bl P256_mulmod
	
	// Now we will check if r*Z^2 = X
	ldr r8,[sp,#68]
	ldm r8!,{r9-r12}
	eors r0,r9
	ittt eq
	eorseq r1,r10
	eorseq r2,r11
	eorseq r3,r12
	ldm r8!,{r9-r12}
	itttt eq
	eorseq r4,r9
	eorseq r5,r10
	eorseq r6,r11
	eorseq r7,r12
	mov r0,#1
	beq 1f
	
	// The check may fail if r < p-n, so also check for r' = r+n
	adr r0,P256_order
	ldm r0,{r8-r11}
	ldr r0,[sp,#64]
	cbz r0,0f // if we already tried once, abort
	ldm r0,{r0-r7}
	adds r0,r8
	adcs r1,r1,r9
	adcs r2,r2,r10
	adcs r3,r3,r11
	adcs r4,r4,#0xffffffff
	adcs r5,r5,#0xffffffff
	adcs r6,r6,#0
	adcs r7,r7,#0xffffffff
	bcs 0f // reject if r+n >= 2^256 (which is >= p)
	
	subs r8,r0,#0xffffffff
	sbcs r8,r1,#0xffffffff
	sbcs r8,r2,#0xffffffff
	sbcs r8,r3,#0
	sbcs r8,r4,#0
	sbcs r8,r5,#0
	sbcs r8,r6,#1
	sbcs r8,r7,#0xffffffff
	bcs 0f // reject if r+n >= p
	
	add r8,sp,#32
	stm r8,{r0-r7}
	movs r2,#0
	str r2,[sp,#64] // set r variable to NULL to avoid yet another try
	
	mov r1,r8
	b 2b

0:
	movs r0,#0
1:
	add sp,#72
	//frame address sp,36
	pop {r4-r11,pc}
	
	.size P256_verify_last_step, .-P256_verify_last_step
#endif

#if include_p256_basemult || include_p256_varmult || include_p256_decompress_point
// in: *r0 = output location, *r1 = input, *r2 = 0/1, *r3 = m
// if r2 = 0, then *r0 is set to *r1
// if r2 = 1, then *r0 is set to m - *r1
// note that *r1 should be in the range [1,m-1]
// out: r0 and r1 will have advanced 32 bytes, r2 will remain as the input
	.type P256_negate_mod_m_if, %function
P256_negate_mod_m_if:
	push {r4-r8,lr}
	//frame push {r4-r8,lr}
	rsb r8,r2,#1
	movs r6,#8
	subs r7,r7 // set r7=0 and C=1
0:
	ldm r1!,{r4,r12}
	ldm r3!,{r5,lr}
	sbcs r5,r5,r4
	umull r4,r7,r8,r4
	umaal r4,r7,r2,r5
	sbcs lr,lr,r12
	umull r12,r7,r8,r12
	umaal r12,r7,r2,lr
	stm r0!,{r4,r12}
	sub r6,#2
	cbz r6,1f
	b 0b
1:
	pop {r4-r8,pc}
	.size P256_negate_mod_m_if, .-P256_negate_mod_m_if
#endif

#if include_p256_basemult || include_p256_varmult
	.type P256_negate_mod_n_if, %function
P256_negate_mod_n_if:
	.global P256_negate_mod_n_if
	ldr r3,=P256_order
	b P256_negate_mod_m_if
	.size P256_negate_mod_n_if, .-P256_negate_mod_n_if

	.type P256_negate_mod_p_if, %function
P256_negate_mod_p_if:
	.global P256_negate_mod_p_if
	adr r3,P256_p
	b P256_negate_mod_m_if
	.size P256_negate_mod_p_if, .-P256_negate_mod_p_if
#endif

	.align 2
	.end
