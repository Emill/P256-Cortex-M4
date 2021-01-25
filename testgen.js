/*
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

// execute "node testgen.js > tests.c", with a nodejs version >= 10.4

const assert = require('assert');
const https = require('https');
const crypto = require('crypto');

// Simple ECDSA implementation that is correct, but slow and not side channel safe. Only used to generate test data.
q = 2n**256n - 2n**224n + 2n**192n + 2n**96n - 1n
G = {x: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n, y: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n}
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n

function div2(v, mod) {
	return (v & 1n) ? (v + mod) >> 1n : v >> 1n;
}

// https://eprint.iacr.org/2014/130.pdf, algorithm 10
function pointDbl(p) {
	t1 = p.z**2n
	t2 = p.x + t1
	t1 = p.x - t1
	t1 = t1 * t2
	t2 = div2(t1, q)
	t1 = t1 + t2
	t2 = p.y**2n
	t3 = p.x * t2
	t4 = t1**2n
	t4 = t4 - t3
	x = t4 - t3
	z = p.y * p.z
	t2 = t2**2n
	t4 = t3 - x
	t1 = t1 * t4
	y = t1 - t2
	return {x: x % q, y: y % q, z: z % q}
}

// https://eprint.iacr.org/2014/130.pdf, algorithm 13
function pointAdd(p1, p2) {
	if (p1.z === 0n) {
		return {x: p2.x, y: p2.y, z: 1n}
	}
	t1 = p1.z**2n
	t2 = p1.z * t1
	t1 = t1 * p2.x
	t2 = t2 * p2.y
	t1 = t1 - p1.x
	t2 = t2 - p1.y
	t1 %= q
	t2 %= q
	if (t1 === 0n) {
		if (t2 === 0n) {
			return pointDbl(p1)
		} else {
			return {x: 0n, y: 0n, z: 0n}
		}
	}
	z = p1.z * t1
	t3 = t1**2n
	t4 = t1 * t3
	t3 = p1.x * t3
	t1 = t3 + t3
	x = t2**2n
	x = x - t1
	x = x - t4
	t3 = t3 - x
	t3 = t2 * t3
	t4 = t4 * p1.y
	y = t3 - t4
	return {x: x % q, y: y % q, z: z % q}
}

// "D. Hankerson, A. Menezes, and S. Vanstone, Guide to
// Elliptic Curve Cryptography, 2004" Algorithm 2.22
// (Extended Stein's GCD algorithm)
function modInv(val, mod) {
	if (val === 0n) {
		return 0n;
	}
	let u = val, v = mod;
	let x1 = 1n, x2 = 0n;
	while (u !== 1n && v !== 1n) {
		while ((u & 1n) === 0n) {
			u = u >> 1n;
			x1 = div2(x1, mod);
		}
		while ((v & 1n) === 0n) {
			v = v >> 1n;
			x2 = div2(x2, mod);
		}
		if (u >= v) {
			u = u - v;
			x1 = x1 - x2;
			if (x1 < 0n) {
				x1 = x1 + mod;
			}
		} else {
			v = v - u;
			x2 = x2 - x1;
			if (x2 < 0n) {
				x2 = x2 + mod;
			}
		}
	}
	return u === 1n ? x1 : x2;
}

function scalarmult(scalar, p) {
	// this implementation does not verify that p lies on the curve
	if (scalar === 0n) {
		return {x: 0n, y: 0n};
	}
	let neg = scalar < 0n;
	if (neg) {
		scalar = -scalar;
	}
	let result = {x: 0n, y: 0n, z: 0n};
	const numBits = scalar.toString(2).length;
	for (let i = numBits - 1; i >= 0; i--) {
		result = pointDbl(result);
		if (scalar & (1n << BigInt(i))) {
			result = pointAdd(result, p);
		}
	}
	if (neg) {
		result.y = -result.y;
	}
	result = {x: (result.x + q) % q, y: (result.y + q) % q, z: (result.z + q) % q};
	const zInv = modInv(result.z, q);
	return {x: (result.x * zInv**2n) % q, y: (result.y * zInv**3n) % q};
}

function sign(z, privKey, k) {
	if ((k < 1n || k >= n) || (privKey < 1n || privKey >= n)) {
		return null;
	}
	const point = scalarmult(k, G);
	const r = point.x % n;
	if (r === 0n) {
		return null;
	}
	const s = modInv(k, n) * (z + r * privKey) % n;
	if (s === 0n) {
		return null;
	}
	return {r: r, s: s};
}

function bufferToBigInt(b) {
	return BigInt('0x' + b.toString('hex'));
}

function bigIntToBuffer(v, len) {
	let str = v.toString(16);
	if (str.length & 1) {
		str = '0' + str;
	}
	let buf = Buffer.from(str, 'hex');
	if (buf.length < len) {
		buf = Buffer.concat([Buffer.alloc(len - buf.length), buf]);
	}
	return buf;
}

function sha256(v) {
	return crypto.createHash('sha256').update(v).digest();
}

function httpsRequest(url) {
	return new Promise((resolve, reject) => {
		let data = '';

		https.get(url, (res) => {
			res.on('data', (chunk) => {
				data += chunk;
			});
			res.on('end', () => {
				resolve(data);
			});
			res.on('error', (error) => {
				reject(error);
			});
		});
	});
}

function toUIntArr(v, size, resizeLen) {
	const len = v.length / size;
	let res = [];
	for (let i = 0; i < len; i++) {
		res.push('0x' + v.slice(i * size, (i + 1) * size).toString('hex'));
	}
	for (let i = 0; i < res.length / resizeLen; i++) {
		const start = i * resizeLen;
		for (let j = 0; j < resizeLen / 2; j++) {
			const v1 = res[start + j];
			const v2 = res[start + resizeLen - 1 - j];
			res[start + j] = v2;
			res[start + resizeLen - 1 - j] = v1;
		}
	}
	
	return '{' + res.join(',') + '}';
}

async function ecdhTests() {
	let data = await httpsRequest('https://raw.githubusercontent.com/google/wycheproof/master/testvectors/ecdh_secp256r1_test.json');
	
	data = JSON.parse(data);
	const testGroups = data.testGroups;
	const newTests = [];
	testGroups.forEach((testGroup) => {
		testGroup.tests.forEach((test) => {
			let pub = Buffer.from(test.public, 'hex');
			const prefix = Buffer.from('301306072a8648ce3d020106082a8648ce3d03010703', 'hex');
			if (pub[0] !== 0x30 || pub[1] !== pub.length - 2 || !pub.slice(2, 24).equals(prefix) || pub[24] !== pub.length - 25 || pub[25] !== 0x00 || (pub[24] !== 66 && pub[24] !== 34)) {
				if (test.flags.some(f => f === 'UnnamedCurve' || f === 'InvalidAsn')) {
					return;
				}
				assert.equal(test.result, 'invalid', test.tcId);
				//console.log(test.tcId + ' ' + test.comment);
				return;
			}
			pub = pub.slice(26);
			
			if (!((pub.length == 65 && pub[0] == 0x04) || (pub.length == 66 && pub[0] != 0x04))) {
				test.result = 'invalid';
				test.shared = '';
			}
			if (pub.equals(Buffer.from('042998705a9a71c783e1cf4397dbed9375a44e4cb88053594b0ea982203b6363b063d0af4971d1c3813db3c7799f9f9324cbe1b90054c81b510ff6297160add6eb', 'hex'))) {
				// Bug in test case #454, should not be accepted, but invalid, since point does not lie on curve
				test.result = 'invalid';
				test.shared = '';
			}
			
			
			let priv = Buffer.from(test.private, 'hex');
			if (priv.length > 32) {
				if (priv.length !== 33 || priv[0] !== 0x00 || priv[1] < 0x80) {
					assert.equal(test.result, 'invalid', test.tcId);
					//console.log(test.tcId + ' ' + test.comment);
					return;
				}
				priv = priv.slice(1);
			} else if (priv.length < 32) {
				priv = Buffer.concat([Buffer.alloc(32 - priv.length), priv]);
			}
			
			const shared = Buffer.from(test.shared, 'hex');
			assert.equal(shared.length === 32, test.result !== 'invalid');
			
			newTests.push({tcId: test.tcId, pub: pub, priv: priv, shared: shared, result: test.result !== 'invalid'});
		});
	});
	const pubs = {}; let pubsSize = 0; const pubsArr = [];
	const privs = {}; let privsSize = 0; const privsArr = [];
	const shareds = {}; let sharedsSize = 0; const sharedsArr = [];
	newTests.forEach((test) => {
		if (!(test.pub.toString('hex') in pubs)) {pubs[test.pub.toString('hex')] = pubsSize++; pubsArr.push(test.pub);}
		if (!(test.priv.toString('hex') in privs)) {privs[test.priv.toString('hex')] = privsSize++; privsArr.push(test.priv);}
		if (test.shared.length && !(test.shared.toString('hex') in shareds)) {shareds[test.shared.toString('hex')] = sharedsSize++; sharedsArr.push(test.shared);}
	});
	const resArr = newTests.map((test) => {
		return ['pub_' + pubs[test.pub.toString('hex')], 'priv_' + privs[test.priv.toString('hex')], test.shared.length ? 'shared_' + shareds[test.shared.toString('hex')] : 'NULL', test.pub.length, test.result ? 1 : 0 /*, test.tcId*/];
	});
	
	const invalidScalars = [0n, n, n + 1n, n + 2n, 2n**256n - 2n, 2n**256n - 1n].map(v => toUIntArr(bigIntToBuffer(v, 32), 4, 8));
	pubsArr.forEach((v, i) => console.log('static const uint8_t pub_' + i + '[] = ' + toUIntArr(v, 1, 1) + ';'));
	privsArr.forEach((v, i) => console.log('static const uint32_t priv_' + i + '[] = ' + toUIntArr(v, 4, 8) + ';'));
	sharedsArr.forEach((v, i) => console.log('static const uint8_t shared_' + i + '[] = ' + toUIntArr(v, 1, 1) + ';'));
	privsArr.forEach((v, i) => {
		const pub = scalarmult(bufferToBigInt(v), G);
		console.log('static const uint32_t pub_for_priv_' + i + '[] = ' + toUIntArr(Buffer.concat([bigIntToBuffer(pub.x, 32), bigIntToBuffer(pub.y, 32)]), 4, 8) + ';');
	});
	console.log('static const struct EcdhTest ecdh_tests[] = {' + resArr.map((test) => '{' + test.join(',') + '}').join(',\n') + '};\n');
	console.log('static const struct KeygenTest keygen_tests_ok[] = {' + privsArr.map((v, i) => '{priv_' + i + ', pub_for_priv_' + i + '}').join(',\n') + '};\n');
	console.log('static const uint32_t keygen_tests_fail[][8] = {' + invalidScalars.join(',\n') + '};\n');
	
	const invalidSignData = [
		{k: 1n, z: n - G.x, priv: 1n},
		{k: 0n, z: 0n, priv: 1n},
		{k: n, z: 0n, priv: 1n}
	];
	const validSignData = [
		{k: 1n, z: 0n, priv: 1n},
		{k: n - 1n, z: 2n**256n - 1n, priv: n - 1n},
		{k: bufferToBigInt(sha256('test0k')), z: bufferToBigInt(sha256('test0z')), priv: bufferToBigInt(sha256('test0p'))},
		{k: bufferToBigInt(sha256('test1k')), z: bufferToBigInt(sha256('test1z')), priv: bufferToBigInt(sha256('test1p'))},
		{k: bufferToBigInt(sha256('test2k')), z: bufferToBigInt(sha256('test2z')), priv: bufferToBigInt(sha256('test2p'))},
		{k: bufferToBigInt(sha256('test3k')), z: bufferToBigInt(sha256('test3z')), priv: bufferToBigInt(sha256('test3p'))},
		{k: bufferToBigInt(sha256('test4k')), z: bufferToBigInt(sha256('test4z')), priv: bufferToBigInt(sha256('test4p'))},
	].map(d => {
		const rs = sign(d.z, d.priv, d.k);
		return {k: d.k, z: d.z, priv: d.priv, r: rs.r, s: rs.s};
	});
	console.log('static const struct InvalidSign invalid_signs[] = {' + invalidSignData.map(d =>
		'{' + toUIntArr(bigIntToBuffer(d.k, 32), 4, 8) + ',\n' + toUIntArr(bigIntToBuffer(d.z, 32), 1, 1) + ',\n' + toUIntArr(bigIntToBuffer(d.priv, 32), 4, 8) + '}'
	).join(',\n') + '};');
	console.log('static const struct ValidSign valid_signs[] = {' + validSignData.map(d =>
		'{' + toUIntArr(bigIntToBuffer(d.k, 32), 4, 8) + ',\n' + toUIntArr(bigIntToBuffer(d.z, 32), 1, 1) + ',\n' + toUIntArr(bigIntToBuffer(d.priv, 32), 4, 8) + ',\n' +
		toUIntArr(Buffer.concat([bigIntToBuffer(d.r, 32), bigIntToBuffer(d.s, 32)]), 4, 8) + '}'
	).join(',\n') + '};');
}

async function ecdsaVerifyTests() {
	let data = await httpsRequest('https://raw.githubusercontent.com/google/wycheproof/master/testvectors/ecdsa_secp256r1_sha256_test.json');
	
	data = JSON.parse(data);
	const testGroups = data.testGroups;
	const newTests = [];
	testGroups.forEach((testGroup) => {
		const publicKey = Buffer.from(testGroup.key.uncompressed.slice(2), 'hex');
		testGroup.tests.forEach((test) => {
			const msg = crypto.createHash('sha256').update(test.msg, 'hex').digest();
			const sig = Buffer.from(test.sig, 'hex');
			if (sig[0] !== 0x30 || sig[1] !== sig.length - 2) {
				assert.equal(test.result, 'invalid');
				//console.log(test.tcId + ' ' + test.comment);
				return;
			}
			let rs = [];
			let pos = 2;
			for (let i = 0; i < 2; i++) {
				const len = sig[pos + 1];
				if (sig[pos] !== 0x02 || len > 33 || len > sig.length - pos - 2) {
					assert.equal(test.result, 'invalid', test.tcId);
					//console.log(test.tcId + ' ' + test.comment);
					return;
				}
				let num = sig.slice(pos + 2, pos + 2 + len);
				if (num.length == 33) {
					if (num[0] !== 0) {
						assert.equal(test.result, 'invalid');
						//console.log(test.tcId + ' ' + test.comment);
						return;
					}
					num = num.slice(1);
				}
				num = Buffer.concat([Buffer.alloc(32 - num.length), num]);
				rs.push(num);
				pos += 2 + len;
			}
			if (pos !== sig.length) {
				assert.equal(test.result, 'invalid');
				return;
			}
			newTests.push({tcId: test.tcId, key: publicKey, msg: msg, sig: Buffer.concat(rs), result: test.result === 'valid' || test.result === 'acceptable'});
		});
	});
	const keys = {}; let keysSize = 0; const keysArr = [];
	const msgs = {}; let msgsSize = 0; const msgsArr = [];
	const sigs = {}; let sigsSize = 0; const sigsArr = [];
	newTests.forEach((test) => {
		if (!(test.key in keys)) {keys[test.key] = keysSize++; keysArr.push(test.key);}
		if (!(test.msg in msgs)) {msgs[test.msg] = msgsSize++; msgsArr.push(test.msg);}
		if (!(test.sig in sigs)) {sigs[test.sig] = sigsSize++; sigsArr.push(test.sig);}
	});
	const resArr = newTests.map((test) => {
		return {key: keys[test.key], msg: msgs[test.msg], sig: sigs[test.sig], result: test.result, tcId: test.tcId};
	}).map((test) => {
		return ['key_' + test.key, 'msg_' + test.msg, 'sig_' + test.sig, test.result ? 1 : 0 /*, test.tcId*/];
	});
	keysArr.forEach((v, i) => console.log('static const uint32_t key_' + i + '[] = ' + toUIntArr(v, 4, 8) + ';'));
	msgsArr.forEach((v, i) => console.log('static const uint8_t msg_' + i + '[] = ' + toUIntArr(v, 1, 1) + ';'));
	sigsArr.forEach((v, i) => console.log('static const uint32_t sig_' + i + '[] = ' + toUIntArr(v, 4, 8) + ';'));
	console.log('static const struct VerifyTest verify_tests[] = {' + resArr.map((test) => '{' + test.join(',') + '}').join(',\n') + '};\n');
}

(async () => {
	console.log(`#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "p256-cortex-m4.h"
#define COUNTOF(a) (sizeof(a) / sizeof((a)[0]))
struct VerifyTest {const uint32_t* key; const uint8_t* msg; const uint32_t* sig; bool result;};
struct EcdhTest {const uint8_t* pub; const uint32_t* priv; const uint8_t* shared; uint8_t publen; bool valid;};
struct KeygenTest {const uint32_t* priv; const uint32_t* pub;};
struct InvalidSign {const uint32_t k[8]; const uint8_t z[32]; const uint32_t priv[8];};
struct ValidSign {const uint32_t k[8]; const uint8_t z[32]; const uint32_t priv[8]; const uint32_t sig[16];};
`)
	await ecdhTests();
	await ecdsaVerifyTests();
	console.log(`
bool run_tests(void) {
	for (int i = 0; i < COUNTOF(verify_tests); i++) {
		const struct VerifyTest* t = &verify_tests[i];
		if (p256_verify(t->key, t->key + 8, t->msg, 32, t->sig, t->sig + 8) != t->result) {
			return false;
		}
	}
	for (int i = 0; i < COUNTOF(ecdh_tests); i++) {
		const struct EcdhTest* t = &ecdh_tests[i];
		uint32_t x[8], y[8];
		uint8_t shared[32];
		if ((p256_octet_string_to_point(x, y, t->pub, t->publen) && p256_ecdh_calc_shared_secret(shared, t->priv, x, y) && memcmp(shared, t->shared, 32) == 0) != t->valid) {
			return false;
		}
	}
	for (int i = 0; i < COUNTOF(keygen_tests_ok); i++) {
		const struct KeygenTest* t = &keygen_tests_ok[i];
		uint32_t pub[16];
		if (!p256_keygen(pub, pub + 8, t->priv) || memcmp(pub, t->pub, 64) != 0) {
			return false;
		}
	}
	for (int i = 0; i < COUNTOF(keygen_tests_fail); i++) {
		uint32_t x[8], y[8];
		if (p256_keygen(x, y, keygen_tests_fail[i])) {
			return false;
		}
	}
	for (int i = 0; i < COUNTOF(invalid_signs); i++) {
		const struct InvalidSign* t = &invalid_signs[i];
		uint32_t sig[16];
		if (p256_sign(sig, sig + 8, t->z, 32, t->priv, t->k)) {
			return false;
		}
	}
	for (int i = 0; i < COUNTOF(valid_signs); i++) {
		const struct ValidSign* t = &valid_signs[i];
		uint32_t sig[16];
		if (!p256_sign(sig, sig + 8, t->z, 32, t->priv, t->k) || memcmp(sig, t->sig, 64) != 0) {
			return false;
		}
	}
	return true;
}
`);
	
})();
