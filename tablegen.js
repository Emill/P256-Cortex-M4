// Generates the precomputed base point tables in p256-cortex-m4.c.
// execute "node tablegen.js > tables.txt", with a nodejs version >= 10.4,
// and replace each table in p256-cortex-m4.c with the one of the same name.

// Simple affine point arithmetic that is correct, but slow and not side channel safe. Only used to generate tables.
const p = 2n**256n - 2n**224n + 2n**192n + 2n**96n - 1n;
const G = {x: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n, y: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n};

function mod(v) {
	v %= p;
	return v < 0n ? v + p : v;
}

// Extended Euclidean algorithm
function modInv(v) {
	let r0 = mod(v), r1 = p, s0 = 1n, s1 = 0n;
	while (r1 !== 0n) {
		const q = r0 / r1;
		[r0, r1] = [r1, r0 - q * r1];
		[s0, s1] = [s1, s0 - q * s1];
	}
	if (r0 !== 1n) {
		throw new Error('not invertible');
	}
	return mod(s0);
}

// null is the point at infinity
function pointAdd(a, b) {
	if (a === null) {
		return b;
	}
	if (b === null) {
		return a;
	}
	let l;
	if (a.x === b.x) {
		if (mod(a.y + b.y) === 0n) {
			return null;
		}
		l = mod(3n * a.x * a.x - 3n) * modInv(2n * a.y);
	} else {
		l = mod(b.y - a.y) * modInv(b.x - a.x);
	}
	const x = mod(l * l - a.x - b.x);
	return {x: x, y: mod(l * (a.x - x) - a.y)};
}

function scalarmult(k, P) {
	let result = null;
	for (let i = BigInt(k.toString(2).length) - 1n; i >= 0n; i--) {
		result = pointAdd(result, result);
		if ((k >> i) & 1n) {
			result = pointAdd(result, P);
		}
	}
	return result;
}

// Montgomery form (R = 2^256) as 8 little endian 32-bit words
function toWords(v) {
	v = mod(v * 2n**256n);
	const words = [];
	for (let i = 0; i < 8; i++) {
		words.push('0x' + ((v >> BigInt(32 * i)) & 0xffffffffn).toString(16));
	}
	return '{' + words.join(', ') + '}';
}

function pointToC(P) {
	return '{' + toWords(P.x) + ',\n' + toWords(P.y) + '}';
}

// Points (2i+1)*mult*G for i = 0..7
function oddMultiplesTable(name, mult) {
	const points = [];
	for (let i = 1n; i <= 15n; i += 2n) {
		points.push(pointToC(scalarmult(i * mult, G)));
	}
	return 'static const uint32_t ' + name + '[8][2][8] = {\n' + points.join(',\n') + '\n};';
}

// Comb table for scalarmult_fixed_base: the 8 points (2^192 +- 2^128 +- 2^64 +- 1)*2^shift*G,
// where bit 0, 1, 2 of the point index selects the sign of 1, 2^64, 2^128 respectively (set: +, clear: -).
function combTable(shift) {
	const points = [];
	for (let mask = 0; mask < 8; mask++) {
		let k = 2n**192n;
		for (let j = 0; j < 3; j++) {
			k += ((mask >> j) & 1 ? 1n : -1n) * 2n**BigInt(64 * j);
		}
		points.push(pointToC(scalarmult(k << BigInt(shift), G)));
	}
	return '{\n' + points.join(',\n') + '\n}';
}

// One table for each multiple of 8 below 64, guarded so that fast_p256_basemult_tables = N
// keeps the N tables 2^(64/N * t), t = 0..N-1.
function combTables() {
	const out = ['static const uint32_t p256_basepoint_precomp2[fast_p256_basemult_tables][8][2][8] =\n{'];
	for (let shift = 0; shift < 64; shift += 8) {
		const guard = shift % 32 === 0 ? null : shift % 16 === 0 ? 'fast_p256_basemult_tables >= 4' : 'fast_p256_basemult_tables == 8';
		if (guard) {
			out.push('#if ' + guard);
		}
		out.push(combTable(shift) + ',');
		if (guard) {
			out.push('#endif');
		}
	}
	out.push('};');
	return out.join('\n');
}

console.log(oddMultiplesTable('p256_basepoint_precomp', 1n));
console.log();
console.log(combTables());
console.log();
console.log(oddMultiplesTable('p256_basepoint_2_128_precomp', 2n**128n));
