#define VERY_EXPENSIVE_BRANCHES 1
#define DEEP_PREPROC_UNROLL 1
#define PRAGMA_UNROLL 1
#define DEEP_VLIW 1
#define AMD_BFI_INT 1

#define bswap32(v)					\
	(((v) >> 24) | (((v) >> 8) & 0xff00) |		\
	 (((v) << 8) & 0xff0000) | ((v) << 24))

#define SECP 1
#undef SECP

#define unroll_5(a) do { a(0) a(1) a(2) a(3) a(4) } while (0)
#define unroll_8(a) do { a(0) a(1) a(2) a(3) a(4) a(5) a(6) a(7) } while (0)
#define unroll_1_7(a) do { a(1) a(2) a(3) a(4) a(5) a(6) a(7) } while (0)
#define unroll_7(a) do { a(0) a(1) a(2) a(3) a(4) a(5) a(6) } while (0)
#define unroll_7_0(a) do { a(7) a(6) a(5) a(4) a(3) a(2) a(1) a(0) } while (0)
#define unroll_7_1(a) do { a(7) a(6) a(5) a(4) a(3) a(2) a(1) } while (0)
#define unroll_16(a) do {				\
	a(0) a(1) a(2) a(3) a(4) a(5) a(6) a(7)		\
	a(8) a(9) a(10) a(11) a(12) a(13) a(14) a(15)	\
	} while (0)
#define unroll_64(a) do {				\
	a(0) a(1) a(2) a(3) a(4) a(5) a(6) a(7)		\
	a(8) a(9) a(10) a(11) a(12) a(13) a(14) a(15)	\
	a(16) a(17) a(18) a(19) a(20) a(21) a(22) a(23) \
	a(24) a(25) a(26) a(27) a(28) a(29) a(30) a(31)	\
	a(32) a(33) a(34) a(35) a(36) a(37) a(38) a(39) \
	a(40) a(41) a(42) a(43) a(44) a(45) a(46) a(47) \
	a(48) a(49) a(50) a(51) a(52) a(53) a(54) a(55) \
	a(56) a(57) a(58) a(59) a(60) a(61) a(62) a(63) \
	} while (0)

#if defined(DEEP_PREPROC_UNROLL)
#define iter_5(a) unroll_5(a)
#define iter_8(a) unroll_8(a)
#define iter_16(a) unroll_16(a)
#define iter_64(a) unroll_64(a)
#else
#define iter_5(a) do {int _i; for (_i = 0; _i < 5; _i++) { a(_i) }} while (0)
#define iter_8(a) do {int _i; for (_i = 0; _i < 8; _i++) { a(_i) }} while (0)
#define iter_16(a) do {int _i; for (_i = 0; _i < 16; _i++) { a(_i) }} while (0)
#define iter_64(a) do {int _i; for (_i = 0; _i < 64; _i++) { a(_i) }} while (0)
#endif

typedef uint bn_word;
#define BN_NBITS 256
#define BN_WSHIFT 5
#define BN_WBITS (1 << BN_WSHIFT)
#define BN_NWORDS ((BN_NBITS/8) / sizeof(bn_word))
#define BN_WORDMAX 0xffffffff

#ifndef SECP
#define MODULUS_BYTES \
0xffffffed, 0xffffffff, 0xffffffff, 0xffffffff, \
0xffffffff, 0xffffffff, 0xffffffff, 0x7fffffff
__constant bn_word mont_rr[BN_NWORDS] = { 0x000005a4, };
__constant bn_word mont_n0[2] = { 0x286bca1b, 0xa86bca1b, }; 
#else
#define MODULUS_BYTES \
0xfffffc2f, 0xfffffffe, 0xffffffff, 0xffffffff, \
0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff
__constant bn_word mont_rr[BN_NWORDS] = { 0xe90a1, 0x7a2, 0x1, 0, 0, 0, 0, 0};   
__constant bn_word mont_n0[2] = { 0xd2253531, }; 
#endif

#define SUBB_BYTES \
0xaaad2451,0xaaaaaaaa,0xaaaaaaaa,0xaaaaaaaa,0xaaaaaaaa,0xaaaaaaaa,0xaaaaaaaa,0x2aaaaaaa

typedef struct {
	bn_word d[BN_NWORDS];
} bignum;

__constant bn_word modulus[] = { MODULUS_BYTES };
__constant bignum bn_zero = {0,0,0,0};
__constant bignum subb = {SUBB_BYTES};

#define bn_is_odd(bn)		(bn.d[0] & 1)
#define bn_is_even(bn) 		(!bn_is_odd(bn))
#define bn_is_zero(bn) 		(!bn.d[0] && !bn.d[1] && !bn.d[2] && \
				 !bn.d[3] && !bn.d[4] && !bn.d[5] && \
				 !bn.d[6] && !bn.d[7])
#define bn_is_one(bn) 		((bn.d[0] == 1) && !bn.d[1] && !bn.d[2] && \
				 !bn.d[3] && !bn.d[4] && !bn.d[5] && \
				 !bn.d[6] && !bn.d[7])
#define bn_is_bit_set(bn, n) \
	((((bn_word*)&bn)[n >> BN_WSHIFT]) & (1 << (n & (BN_WBITS-1))))

#define bn_unroll(e) unroll_8(e)
#define bn_unroll_sf(e)	unroll_1_7(e)
#define bn_unroll_sl(e)	unroll_7(e)
#define bn_unroll_reverse(e) unroll_7_0(e)
#define bn_unroll_reverse_sl(e) unroll_7_1(e)

#define bn_unroll_arg(e, arg)				\
	e(arg, 0) e(arg, 1) e(arg, 2) e(arg, 3)	\
	e(arg, 4) e(arg, 5) e(arg, 6) e(arg, 7)
#define bn_unroll_arg_sf(e, arg)			\
	e(arg, 1) e(arg, 2) e(arg, 3)		\
	e(arg, 4) e(arg, 5) e(arg, 6) e(arg, 7)

#define bn_iter(e) iter_8(e)


void
bn_lshift1(bignum *bn)
{
#define bn_lshift1_inner1(i)						\
		bn->d[i] = (bn->d[i] << 1) | (bn->d[i-1] >> 31);
	bn_unroll_reverse_sl(bn_lshift1_inner1);
	bn->d[0] <<= 1;
}

void
bn_rshift(bignum *bn, int shift)
{
	int wd, iws, iwr;
	bn_word ihw, ilw;
	iws = (shift & (BN_WBITS-1));
	iwr = BN_WBITS - iws;
	wd = (shift >> BN_WSHIFT);
	ihw = (wd < BN_WBITS) ? bn->d[wd] : 0;

#define bn_rshift_inner1(i)				\
		wd++;					\
		ilw = ihw;				\
		ihw = (wd < BN_WBITS) ? bn->d[wd] : 0;	\
		bn->d[i] = (ilw >> iws) | (ihw << iwr);
	bn_unroll_sl(bn_rshift_inner1);
	bn->d[BN_NWORDS-1] = (ihw >> iws);
}

void
bn_rshift1(bignum *bn)
{
#define bn_rshift1_inner1(i)						\
		bn->d[i] = (bn->d[i+1] << 31) | (bn->d[i] >> 1);
	bn_unroll_sl(bn_rshift1_inner1);
	bn->d[BN_NWORDS-1] >>= 1;
}

void
bn_rshift1_2(bignum *bna, bignum *bnb)
{
#define bn_rshift1_2_inner1(i)						\
		bna->d[i] = (bna->d[i+1] << 31) | (bna->d[i] >> 1);	\
		bnb->d[i] = (bnb->d[i+1] << 31) | (bnb->d[i] >> 1);
	bn_unroll_sl(bn_rshift1_2_inner1);
	bna->d[BN_NWORDS-1] >>= 1;
	bnb->d[BN_NWORDS-1] >>= 1;
}


int
bn_ucmp_ge(bignum *a, bignum *b)
{
	int l = 0, g = 0;

#define bn_ucmp_ge_inner1(i)				\
		if (a->d[i] < b->d[i]) l |= (1 << i);	\
		if (a->d[i] > b->d[i]) g |= (1 << i);
	bn_unroll_reverse(bn_ucmp_ge_inner1);
	return (l > g) ? 0 : 1;
}

int
bn_ucmp_ge_c(bignum *a, __constant bn_word *b)
{
	int l = 0, g = 0;

#define bn_ucmp_ge_c_inner1(i)				\
		if (a->d[i] < b[i]) l |= (1 << i);	\
		if (a->d[i] > b[i]) g |= (1 << i);
	bn_unroll_reverse(bn_ucmp_ge_c_inner1);
	return (l > g) ? 0 : 1;
}


void
bn_neg(bignum *n)
{
	int c = 1;

#define bn_neg_inner1(i)				\
		c = (n->d[i] = (~n->d[i]) + c) ? 0 : c;
	bn_unroll(bn_neg_inner1);
}


#define bn_add_word(r, a, b, t, c) do {		\
		t = a + b;			\
		c = (t < a) ? 1 : 0;		\
		r = t;				\
	} while (0)

#define bn_addc_word(r, a, b, t, c) do {			\
		t = a + b + c;					\
		c = (t < a) ? 1 : ((c & (t == a)) ? 1 : 0);	\
		r = t;						\
	} while (0)

bn_word
bn_uadd_words_seq(bn_word *r, bn_word *a, bn_word *b)
{
	bn_word t, c = 0;

#define bn_uadd_words_seq_inner1(i)			\
		bn_addc_word(r[i], a[i], b[i], t, c);
	bn_add_word(r[0], a[0], b[0], t, c);
	bn_unroll_sf(bn_uadd_words_seq_inner1);
	return c;
}

bn_word
bn_uadd_words_c_seq(bn_word *r, bn_word *a, __constant bn_word *b)
{
	bn_word t, c = 0;

	bn_add_word(r[0], a[0], b[0], t, c);
	bn_unroll_sf(bn_uadd_words_seq_inner1);
	return c;
}

#define bn_sub_word(r, a, b, t, c) do {		\
		t = a - b;			\
		c = (a < b) ? 1 : 0;		\
		r = t;				\
	} while (0)

#define bn_subb_word(r, a, b, t, c) do {	\
		t = a - (b + c);		\
		c = (!(a) && c) ? 1 : 0;	\
		c |= (a < b) ? 1 : 0;		\
		r = t;				\
	} while (0)

bn_word
bn_usub_words_seq(bn_word *r, bn_word *a, bn_word *b)
{
	bn_word t, c = 0;

#define bn_usub_words_seq_inner1(i)			\
		bn_subb_word(r[i], a[i], b[i], t, c);

	bn_sub_word(r[0], a[0], b[0], t, c);
	bn_unroll_sf(bn_usub_words_seq_inner1);
	return c;
}


bn_word
bn_usub_words_c_seq(bn_word *r, bn_word *a, __constant bn_word *b)
{
	bn_word t, c = 0;

	bn_sub_word(r[0], a[0], b[0], t, c);
	bn_unroll_sf(bn_usub_words_seq_inner1);
	return c;
}

bn_word
bn_uadd_words_vliw(bn_word *r, bn_word *a, bn_word *b)
{
	bignum x;
	bn_word c = 0, cp = 0;

#define bn_uadd_words_vliw_inner1(i)		\
		x.d[i] = a[i] + b[i];

#define bn_uadd_words_vliw_inner2(i)			\
		c |= (a[i] > x.d[i]) ? (1 << i) : 0;	\
		cp |= (!~x.d[i]) ? (1 << i) : 0;

#define bn_uadd_words_vliw_inner3(i)		\
		r[i] = x.d[i] + ((c >> i) & 1);

	bn_unroll(bn_uadd_words_vliw_inner1);
	bn_unroll(bn_uadd_words_vliw_inner2);
	c = ((cp + (c << 1)) ^ cp);
	r[0] = x.d[0];
	bn_unroll_sf(bn_uadd_words_vliw_inner3);
	return c >> BN_NWORDS;
}

bn_word
bn_uadd_words_c_vliw(bn_word *r, bn_word *a, __constant bn_word *b)
{
	bignum x;
	bn_word c = 0, cp = 0;

	bn_unroll(bn_uadd_words_vliw_inner1);
	bn_unroll(bn_uadd_words_vliw_inner2);
	c = ((cp + (c << 1)) ^ cp);
	r[0] = x.d[0];
	bn_unroll_sf(bn_uadd_words_vliw_inner3);
	return c >> BN_NWORDS;
}

bn_word
bn_usub_words_vliw(bn_word *r, bn_word *a, bn_word *b)
{
	bignum x;
	bn_word c = 0, cp = 0;

#define bn_usub_words_vliw_inner1(i)		\
		x.d[i] = a[i] - b[i];

#define bn_usub_words_vliw_inner2(i)			\
		c |= (a[i] < b[i]) ? (1 << i) : 0;	\
		cp |= (!x.d[i]) ? (1 << i) : 0;

#define bn_usub_words_vliw_inner3(i)		\
		r[i] = x.d[i] - ((c >> i) & 1);

	bn_unroll(bn_usub_words_vliw_inner1);
	bn_unroll(bn_usub_words_vliw_inner2);
	c = ((cp + (c << 1)) ^ cp);
	r[0] = x.d[0];
	bn_unroll_sf(bn_usub_words_vliw_inner3);
	return c >> BN_NWORDS;
}

bn_word
bn_usub_words_c_vliw(bn_word *r, bn_word *a, __constant bn_word *b)
{
	bignum x;
	bn_word c = 0, cp = 0;

	bn_unroll(bn_usub_words_vliw_inner1);
	bn_unroll(bn_usub_words_vliw_inner2);
	c = ((cp + (c << 1)) ^ cp);
	r[0] = x.d[0];
	bn_unroll_sf(bn_usub_words_vliw_inner3);
	return c >> BN_NWORDS;
}


#if defined(DEEP_VLIW)
#define bn_uadd_words bn_uadd_words_vliw
#define bn_uadd_words_c bn_uadd_words_c_vliw
#define bn_usub_words bn_usub_words_vliw
#define bn_usub_words_c bn_usub_words_c_vliw
#else
#define bn_uadd_words bn_uadd_words_seq
#define bn_uadd_words_c bn_uadd_words_c_seq
#define bn_usub_words bn_usub_words_seq
#define bn_usub_words_c bn_usub_words_c_seq
#endif

#define bn_uadd(r, a, b) bn_uadd_words((r)->d, (a)->d, (b)->d)
#define bn_uadd_c(r, a, b) bn_uadd_words_c((r)->d, (a)->d, b)
#define bn_usub(r, a, b) bn_usub_words((r)->d, (a)->d, (b)->d)
#define bn_usub_c(r, a, b) bn_usub_words_c((r)->d, (a)->d, b)


void
bn_mod_add(bignum *r, bignum *a, bignum *b)
{
	if (bn_uadd(r, a, b) ||
	    (bn_ucmp_ge_c(r, modulus)))
		bn_usub_c(r, r, modulus);
}

void
bn_mod_sub(bignum *r, bignum *a, bignum *b)
{
	if (bn_usub(r, a, b))
		bn_uadd_c(r, r, modulus);
}

void
bn_mod_lshift1(bignum *bn)
{
	bn_word c = (bn->d[BN_NWORDS-1] & 0x80000000);
	bn_lshift1(bn);
	if (c || (bn_ucmp_ge_c(bn, modulus)))
		bn_usub_c(bn, bn, modulus);
}


#define bn_mul_word(r, a, w, c, p, s) do { \
		r = (a * w) + c;	   \
		p = mul_hi(a, w);	   \
		c = (r < c) ? p + 1 : p;   \
	} while (0)

#define bn_mul_add_word(r, a, w, c, p, s) do {	\
		s = r + c;			\
		p = mul_hi(a, w);		\
		r = (a * w) + s;		\
		c = (s < c) ? p + 1 : p;	\
		if (r < s) c++;			\
	} while (0)




void
bn_mul_mont(bignum *r, bignum *a, bignum *b)
{
	bignum t;
	bn_word tea, teb, c, p, s, m;

#if !defined(VERY_EXPENSIVE_BRANCHES)
	int q;
#endif

	c = 0;
#define bn_mul_mont_inner1(j)					\
		bn_mul_word(t.d[j], a->d[j], b->d[0], c, p, s);
	bn_unroll(bn_mul_mont_inner1);
	tea = c;
	teb = 0;

	c = 0;
	m = t.d[0] * mont_n0[0];
	bn_mul_add_word(t.d[0], modulus[0], m, c, p, s);
#define bn_mul_mont_inner2(j)						\
		bn_mul_add_word(t.d[j], modulus[j], m, c, p, s);	\
		t.d[j-1] = t.d[j];
	bn_unroll_sf(bn_mul_mont_inner2);
	t.d[BN_NWORDS-1] = tea + c;
	tea = teb + ((t.d[BN_NWORDS-1] < c) ? 1 : 0);

#define bn_mul_mont_inner3_1(i, j)					\
		bn_mul_add_word(t.d[j], a->d[j], b->d[i], c, p, s);
#define bn_mul_mont_inner3_2(i, j)					\
		bn_mul_add_word(t.d[j], modulus[j], m, c, p, s);	\
		t.d[j-1] = t.d[j];
#define bn_mul_mont_inner3(i)				 \
	c = 0;						 \
	bn_unroll_arg(bn_mul_mont_inner3_1, i);		 \
	tea += c;					 \
	teb = ((tea < c) ? 1 : 0);			 \
	c = 0;						 \
	m = t.d[0] * mont_n0[0];			 \
	bn_mul_add_word(t.d[0], modulus[0], m, c, p, s); \
	bn_unroll_arg_sf(bn_mul_mont_inner3_2, i);	 \
	t.d[BN_NWORDS-1] = tea + c;			 \
	tea = teb + ((t.d[BN_NWORDS-1] < c) ? 1 : 0);

	
#if defined(VERY_EXPENSIVE_BRANCHES)
	bn_unroll_sf(bn_mul_mont_inner3);
	c = tea | !bn_usub_c(r, &t, modulus);
	if (!c)
		*r = t;

#else
	for (q = 1; q < BN_NWORDS; q++) {
		bn_mul_mont_inner3(q);
	}
	c = tea || (t.d[BN_NWORDS-1] >= modulus[BN_NWORDS-1]);
	if (c) {
		c = tea | !bn_usub_c(r, &t, modulus);
		if (c)
			return;
	}
	*r = t;
#endif
}

void
bn_from_mont(bignum *rb, bignum *b)
{
#define WORKSIZE ((2*BN_NWORDS) + 1)
	bn_word r[WORKSIZE];
	bn_word m, c, p, s;
#if defined(PRAGMA_UNROLL)
	int i;
#endif


#define bn_from_mont_inner1(i)			\
	r[i] = b->d[i];
#define bn_from_mont_inner2(i)			\
	r[BN_NWORDS+i] = 0;

	bn_unroll(bn_from_mont_inner1);
	bn_unroll(bn_from_mont_inner2);
	r[WORKSIZE-1] = 0;

#define bn_from_mont_inner3_1(i, j) \
	bn_mul_add_word(r[i+j], modulus[j], m, c, p, s);

#if !defined(VERY_EXPENSIVE_BRANCHES)
#define bn_from_mont_inner3_2(i)		\
	if (r[BN_NWORDS + i] < c)		\
		r[BN_NWORDS + i + 1] += 1;
#else
#define bn_from_mont_inner3_2(i)				\
	r[BN_NWORDS + i + 1] += (r[BN_NWORDS + i] < c) ? 1 : 0;
#endif

#define bn_from_mont_inner3(i)			 \
	m = r[i] * mont_n0[0];			 \
	c = 0;					 \
	bn_unroll_arg(bn_from_mont_inner3_1, i); \
	r[BN_NWORDS + i] += c;			 \
	bn_from_mont_inner3_2(i)


#if !defined(PRAGMA_UNROLL)
	bn_iter(bn_from_mont_inner3);
#else
#pragma unroll 8
	for (i = 0; i < BN_NWORDS; i++) { bn_from_mont_inner3(i) }
#endif

	c = bn_usub_words_c(rb->d, &r[BN_NWORDS], modulus);
	if (c) {
#define bn_from_mont_inner4(i)				\
			rb->d[i] = r[BN_NWORDS + i];
		bn_unroll(bn_from_mont_inner4);
	}
}

void
bn_mod_inverse(bignum *r, bignum *n)
{
	bignum a, b, x, y;
	int shift;
	bn_word xc, yc;
	for (shift = 0; shift < BN_NWORDS; shift++) {
		a.d[shift] = modulus[shift];
		x.d[shift] = 0;
		y.d[shift] = 0;
	}
	b = *n;
	x.d[0] = 1;
	xc = 0;
	yc = 0;
	while (!bn_is_zero(b)) {
		shift = 0;
		while (!bn_is_odd(b)) {
			if (bn_is_odd(x))
				xc += bn_uadd_c(&x, &x, modulus);
			bn_rshift1_2(&x, &b);
			x.d[7] |= (xc << 31);
			xc >>= 1;
		}

		while (!bn_is_odd(a)) {
			if (bn_is_odd(y))
				yc += bn_uadd_c(&y, &y, modulus);
			bn_rshift1_2(&y, &a);
			y.d[7] |= (yc << 31);
			yc >>= 1;
		}

		if (bn_ucmp_ge(&b, &a)) {
			xc += yc + bn_uadd(&x, &x, &y);
			bn_usub(&b, &b, &a);
		} else {
			yc += xc + bn_uadd(&y, &y, &x);
			bn_usub(&a, &a, &b);
		}
	}

	if (!bn_is_one(a)) {
		*r = bn_zero;
	} else {
		while (yc < 0x80000000)
			yc -= bn_usub_c(&y, &y, modulus);
		bn_neg(&y);
		*r = y;
	}
}


#define hash256_unroll(a) unroll_8(a)
#define hash160_unroll(a) unroll_5(a)
#define hash256_iter(a) iter_8(a)
#define hash160_iter(a) iter_5(a)

__constant uint sha2_init[8] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

__constant uint sha2_k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void
sha2_256_init(uint *out)
{
#define sha2_256_init_inner_1(i) \
	out[i] = sha2_init[i];

	hash256_unroll(sha2_256_init_inner_1);
}

#define sha2_stvar(vals, i, v) vals[(64+v-i) % 8]
#define sha2_s0(a) (rotate(a, 30U) ^ rotate(a, 19U) ^ rotate(a, 10U))
#define sha2_s1(a) (rotate(a, 26U) ^ rotate(a, 21U) ^ rotate(a, 7U))
#if defined(AOMD_BFI_INT)
#pragma OPENCL EXTENSION cl_amd_media_ops : enable
#define sha2_ch(a, b, c) amd_bytealign(a, b, c)
#define sha2_ma(a, b, c) amd_bytealign((a^c), b, a)
#else
#define sha2_ch(a, b, c) (c ^ (a & (b ^ c)))
#define sha2_ma(a, b, c) ((a & c) | (b & (a | c)))
#endif

void
sha2_256_block(uint *out, uint *in)
{
	uint state[8], t1, t2;
#if defined(PRAGMA_UNROLL)
	int i;
#endif

#define sha2_256_block_inner_1(i) \
	state[i] = out[i];
	hash256_unroll(sha2_256_block_inner_1);

#define sha2_256_block_inner_2(i) \
	if (i >= 16) {							\
		t1 = in[(i + 1) % 16];					\
		t2 = in[(i + 14) % 16];					\
		in[i % 16] += (in[(i + 9) % 16] +			\
		       (rotate(t1, 25U) ^ rotate(t1, 14U) ^ (t1 >> 3)) + \
		       (rotate(t2, 15U) ^ rotate(t2, 13U) ^ (t2 >> 10))); \
	}								\
	t1 = (sha2_stvar(state, i, 7) +					\
	      sha2_s1(sha2_stvar(state, i, 4)) +			\
	      sha2_ch(sha2_stvar(state, i, 4),				\
		      sha2_stvar(state, i, 5),				\
		      sha2_stvar(state, i, 6)) +			\
	      sha2_k[i] +						\
	      in[i % 16]);						\
	t2 = (sha2_s0(sha2_stvar(state, i, 0)) +			\
	      sha2_ma(sha2_stvar(state, i, 0),				\
		      sha2_stvar(state, i, 1),				\
		      sha2_stvar(state, i, 2)));			\
	sha2_stvar(state, i, 3) += t1;					\
	sha2_stvar(state, i, 7) = t1 + t2;				\

#if !defined(PRAGMA_UNROLL)
	iter_64(sha2_256_block_inner_2);
#else
#pragma unroll 64
	for (i = 0; i < 64; i++) { sha2_256_block_inner_2(i) }
#endif
#define sha2_256_block_inner_3(i) \
	out[i] += state[i];

	hash256_unroll(sha2_256_block_inner_3);
}



__kernel void
test_mul_mont(__global bignum *products_out, __global bignum *nums_in)
{
	bignum a, b, c;
	int o;
	o = get_global_id(0);
	nums_in += (2*o);

	a = nums_in[0];
	b = nums_in[1];
	
	bn_mul_mont(&c, &a, &b);
	bn_from_mont(&c, &c);


	

	products_out[o] = c;
}

__kernel void
test_mod_add(__global bignum *products_out, __global bignum *nums_in)
{
	bignum a, b, c;
	int o;
	o = get_global_id(0);
	nums_in += (2*o);

	a = nums_in[0];
	b = nums_in[1];
	bn_mod_add(&c, &a, &b);
	bn_from_mont(&c, &c);


	products_out[o] = c;
}


__kernel void
test_mod_inverse(__global bignum *inv_out, __global bignum *nums_in)
{
	bignum x, xp;
	int i, o, count;
	count = 1;
	o = get_global_id(0) * count;
	for (i = 0; i < count; i++) {
		x = nums_in[o];
		bn_mod_inverse(&xp, &x);
		inv_out[o++] = xp;
	}
}


#define ACCESS_BUNDLE 1024
#define ACCESS_STRIDE (ACCESS_BUNDLE/BN_NWORDS)

__kernel void
ec_add_grid(__global bn_word *points_out, __global bn_word *z_heap, 
	    __global bn_word *row_in, __global bignum *col_in)
{	
	bignum rx, ry;
	bignum x1, y1, a, b, c, d, e, z;
	bn_word cy;
	int i, cell, start;

	i = 2 * get_global_id(1);
	rx = col_in[i];
	ry = col_in[i+1];

	cell = get_global_id(0);
	start = ((((2 * cell) / ACCESS_STRIDE) * ACCESS_BUNDLE) +
		 (cell % (ACCESS_STRIDE/2)));

#define ec_add_grid_inner_1(i) \
	x1.d[i] = row_in[start + (i*ACCESS_STRIDE)];

	bn_unroll(ec_add_grid_inner_1);
	start += (ACCESS_STRIDE/2);

#define ec_add_grid_inner_2(i) \
	y1.d[i] = row_in[start + (i*ACCESS_STRIDE)];

	bn_unroll(ec_add_grid_inner_2);

	bn_mod_sub(&z, &x1, &rx);

	cell += (get_global_id(1) * get_global_size(0));
	start = (((cell / ACCESS_STRIDE) * ACCESS_BUNDLE) +
		 (cell % ACCESS_STRIDE));

#define ec_add_grid_inner_3(i) \
	z_heap[start + (i*ACCESS_STRIDE)] = z.d[i];

	bn_unroll(ec_add_grid_inner_3);

	bn_mod_sub(&b, &y1, &ry);
	bn_mod_add(&c, &x1, &rx);
	bn_mod_add(&d, &y1, &ry);
	bn_mul_mont(&y1, &b, &b);
	bn_mul_mont(&x1, &z, &z);
	bn_mul_mont(&e, &c, &x1);
	bn_mod_sub(&y1, &y1, &e);

	start = ((((2 * cell) / ACCESS_STRIDE) * ACCESS_BUNDLE) +
		 (cell % (ACCESS_STRIDE/2)));

#define ec_add_grid_inner_4(i) \
	points_out[start + (i*ACCESS_STRIDE)] = y1.d[i];

	bn_unroll(ec_add_grid_inner_4);

	bn_mod_lshift1(&y1);
	bn_mod_sub(&y1, &e, &y1);
	bn_mul_mont(&y1, &y1, &b);
	bn_mul_mont(&a, &x1, &z);
	bn_mul_mont(&c, &d, &a);
	bn_mod_sub(&y1, &y1, &c);
	cy = 0;
	if (bn_is_odd(y1))
		cy = bn_uadd_c(&y1, &y1, modulus);
	bn_rshift1(&y1);
	y1.d[BN_NWORDS-1] |= (cy ? 0x80000000 : 0);

	start += (ACCESS_STRIDE/2);

	bn_unroll(ec_add_grid_inner_4);


}

__kernel void
heap_invert(__global bn_word *z_heap, int batch)
{


	bignum a, b, c, z;
	int i, off, lcell, hcell, start;

#define heap_invert_inner_load_a(j)				\
		a.d[j] = z_heap[start + j*ACCESS_STRIDE];
#define heap_invert_inner_load_b(j)				\
		b.d[j] = z_heap[start + j*ACCESS_STRIDE];
#define heap_invert_inner_load_z(j)				\
		z.d[j] = z_heap[start + j*ACCESS_STRIDE];
#define heap_invert_inner_store_z(j)				\
		z_heap[start + j*ACCESS_STRIDE] = z.d[j];
#define heap_invert_inner_store_c(j)				\
		z_heap[start + j*ACCESS_STRIDE] = c.d[j];

	off = get_global_size(0);
	lcell = get_global_id(0);
	hcell = (off * batch) + lcell;
	for (i = 0; i < (batch-1); i++) {

		start = (((lcell / ACCESS_STRIDE) * ACCESS_BUNDLE) +
			 (lcell % ACCESS_STRIDE));

		bn_unroll(heap_invert_inner_load_a);

		lcell += off;
		start = (((lcell / ACCESS_STRIDE) * ACCESS_BUNDLE) +
			 (lcell % ACCESS_STRIDE));

		bn_unroll(heap_invert_inner_load_b);

		bn_mul_mont(&z, &a, &b);

		start = (((hcell / ACCESS_STRIDE) * ACCESS_BUNDLE) +
			 (hcell % ACCESS_STRIDE));

		bn_unroll(heap_invert_inner_store_z);

		lcell += off;
		hcell += off;
	}

	bn_mod_inverse(&z, &z);

#define heap_invert_inner_1(i)			\
	a.d[i] = mont_rr[i];

	bn_unroll(heap_invert_inner_1);

	bn_mul_mont(&z, &z, &a);
	bn_mul_mont(&z, &z, &a);

	lcell -= (off << 1);
	hcell -= (off << 1);

	start = (((lcell / ACCESS_STRIDE) * ACCESS_BUNDLE) +
		 (lcell % ACCESS_STRIDE));
	bn_unroll(heap_invert_inner_load_a);

	lcell += off;
	start = (((lcell / ACCESS_STRIDE) * ACCESS_BUNDLE) +
		 (lcell % ACCESS_STRIDE));
	bn_unroll(heap_invert_inner_load_b);

	bn_mul_mont(&c, &a, &z);

	bn_unroll(heap_invert_inner_store_c);

	bn_mul_mont(&c, &b, &z);

	lcell -= off;
	start = (((lcell / ACCESS_STRIDE) * ACCESS_BUNDLE) +
		 (lcell % ACCESS_STRIDE));
	bn_unroll(heap_invert_inner_store_c);

	lcell -= (off << 1);

	for (i = 0; i < (batch-2); i++) {
		start = (((hcell / ACCESS_STRIDE) * ACCESS_BUNDLE) +
			 (hcell % ACCESS_STRIDE));
		bn_unroll(heap_invert_inner_load_z);

		start = (((lcell / ACCESS_STRIDE) * ACCESS_BUNDLE) +
			 (lcell % ACCESS_STRIDE));
		bn_unroll(heap_invert_inner_load_a);

		lcell += off;
		start = (((lcell / ACCESS_STRIDE) * ACCESS_BUNDLE) +
			 (lcell % ACCESS_STRIDE));
		bn_unroll(heap_invert_inner_load_b);

		bn_mul_mont(&c, &a, &z);

		bn_unroll(heap_invert_inner_store_c);

		bn_mul_mont(&c, &b, &z);

		lcell -= off;
		start = (((lcell / ACCESS_STRIDE) * ACCESS_BUNDLE) +
			 (lcell % ACCESS_STRIDE));
		bn_unroll(heap_invert_inner_store_c);

		lcell -= (off << 1);
		hcell -= off;
	}
}

void
hash_ec_point(uint *hash_out, __global bn_word *xy, __global bn_word *zip)
{
	
	uint hash1[16], hash2[16];
	bignum c, zi, zzi;
	bn_word wh, wl;

	hash1[0] = 0; 
	hash1[1] = 0;
	hash1[2] = 0;
	hash1[3] = 0;
	hash1[4] = 0;
	hash1[5] = 0;
	hash1[6] = 0;
	hash1[7] = 0;
	hash1[8] = 0x80000000;
	hash1[9] = 0;
	hash1[10] = 0;
	hash1[11] = 0;
	hash1[12] = 0;
	hash1[13] = 0;
	hash1[14] = 0;
	hash1[15] = 0x100;

#define hash_ec_point_inner_1(i)		\
	zi.d[i] = zip[i*ACCESS_STRIDE];

	bn_unroll(hash_ec_point_inner_1);

	bn_mul_mont(&zzi, &zi, &zi);  


#define hash_ec_point_inner_2(i)		\
	c.d[i] = xy[i*ACCESS_STRIDE];

	bn_unroll(hash_ec_point_inner_2);

	bn_mul_mont(&c, &c, &zzi);  
	bn_from_mont(&c, &c);


	bn_mod_sub(&c,&c,&subb);

	#define hash_ec_point_inner_3(i)		\
		hash1[7-i] = bswap32(c.d[(BN_NWORDS - 1) - i]);
		bn_unroll(hash_ec_point_inner_3);
	
	 

	sha2_256_init(hash2);
	sha2_256_block(hash2, hash1);

	
#define hash_ec_point_inner_6(i)		\
hash_out[i] = bswap32(hash2[i]);

unroll_8(hash_ec_point_inner_6);

}


void
hash_ec_point_normalize_only(uint *hash_out, __global bn_word *xy, __global bn_word *zip)
{
	
	uint hash1[8];
	bignum c, zi, zzi;
	bn_word wh, wl;


#define hash_ec_point_inner_1(i)		\
	zi.d[i] = zip[i*ACCESS_STRIDE];

	bn_unroll(hash_ec_point_inner_1);

	bn_mul_mont(&zzi, &zi, &zi);  


#define hash_ec_point_inner_2(i)		\
	c.d[i] = xy[i*ACCESS_STRIDE];

	bn_unroll(hash_ec_point_inner_2);

	bn_mul_mont(&c, &c, &zzi);  
	bn_from_mont(&c, &c);


	bn_mod_sub(&c,&c,&subb);

	#define hash_ec_point_inner_3(i)		\
		hash1[7-i] = bswap32(c.d[(BN_NWORDS - 1) - i]);
		bn_unroll(hash_ec_point_inner_3);
	

	
#define hash_ec_point_inner_6(i)		\
hash_out[i] = bswap32(hash1[i]);

unroll_8(hash_ec_point_inner_6);

}
__kernel void
hash_ec_point_search_prefix(__global uint *found,
			    __global bn_word *points_in,
			    __global bn_word *z_heap,
			    __global uint *target_table, int ntargets)
{

	uint hash[8];
	int i, high, low, p, cell, start;

	cell = ((get_global_id(1) * get_global_size(0)) + get_global_id(0));
	start = (((cell / ACCESS_STRIDE) * ACCESS_BUNDLE) +
		 (cell % ACCESS_STRIDE));
	z_heap += start;

	start = ((((2 * cell) / ACCESS_STRIDE) * ACCESS_BUNDLE) +
		 (cell % (ACCESS_STRIDE/2)));
	points_in += start;

	hash_ec_point(hash, points_in, z_heap);



if((bswap32(hash[0])==0xe239bdb) || (bswap32(hash[0])==0xa0860100) || (bswap32(hash[0])==0xba2d6f04) || (bswap32(hash[0])==0xb2158bcb) || (bswap32(hash[0])==0xb60166f3) || (bswap32(hash[0])==0x65ae467f) || (bswap32(hash[0])==0x25c5a207) || (bswap32(hash[0])==0x28dca32c) || (bswap32(hash[0])==0xe2ea7edf) || (bswap32(hash[0])==0x1febd530) || (bswap32(hash[0])==0x4e6e2b3d) || (bswap32(hash[0])==0xb1efa06b) || (bswap32(hash[0])==0xc846bf0c) || (bswap32(hash[0])==0x86c6087d) || (bswap32(hash[0])==0x4fa8cf07) || (bswap32(hash[0])==0x861fc1a3) || (bswap32(hash[0])==0xba973233) || (bswap32(hash[0])==0xe708b03a) || (bswap32(hash[0])==0x6e01b0b7) || (bswap32(hash[0])==0xed66fe31) || (bswap32(hash[0])==0xf297ad07) || (bswap32(hash[0])==0x1c96882c) || (bswap32(hash[0])==0x780ad9aa)){
			found[0] = ((get_global_id(1) * get_global_size(0)) +
				    get_global_id(0));
			found[1] = 0;
#define hash_ec_point_search_prefix_inner_2(i)	\
			found[i+2] = (hash[i]);
			hash160_unroll(hash_ec_point_search_prefix_inner_2);
	}
	
}

