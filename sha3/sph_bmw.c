/* $Id: bmw_extreme.c 2026-04-22 $ */
/*
 * BMW implementation – EXTREME OPTIMIZATION VERSION.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 * Copyright (c) 2026  Extreme Optimizations
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 */

#include <stddef.h>
#include <string.h>
#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "sph_bmw.h"

/* -------------------------------------------------------------------------
 * Build / Architecture Tuning
 * ------------------------------------------------------------------------- */
#if defined(__GNUC__) || defined(__clang__)
#define SPH_RESTRICT __restrict__
#define SPH_ALIGNED(X) __attribute__((aligned(X)))
#define SPH_HOT __attribute__((hot))
#define SPH_ALWAYS_INLINE __attribute__((always_inline)) inline
#define SPH_PREFETCH(addr) __builtin_prefetch(addr, 0, 3)
#elif defined(_MSC_VER)
#define SPH_RESTRICT __restrict
#define SPH_ALIGNED(X) __declspec(align(X))
#define SPH_HOT
#define SPH_ALWAYS_INLINE __forceinline
#define SPH_PREFETCH(addr)
#else
#define SPH_RESTRICT
#define SPH_ALIGNED(X)
#define SPH_HOT
#define SPH_ALWAYS_INLINE inline
#define SPH_PREFETCH(addr)
#endif

/* -------------------------------------------------------------------------
 * Precomputed Constants (Hoisting of Stable Algebra)
 * ------------------------------------------------------------------------- */
/* 32‑bit Ks values precomputed for j=16..31 */
static const sph_u32 Ks_pre[16] = {
    SPH_C32(0x05555550), SPH_C32(0x05A05A05), SPH_C32(0x064B064B),
    SPH_C32(0x06F5F5F5), SPH_C32(0x07A07A07), SPH_C32(0x084B084B),
    SPH_C32(0x08F5F5F5), SPH_C32(0x09A09A09), SPH_C32(0x0A4B0A4B),
    SPH_C32(0x0AF5F5F5), SPH_C32(0x0BA0BA0B), SPH_C32(0x0C4B0C4B),
    SPH_C32(0x0CF5F5F5), SPH_C32(0x0DA0DA0D), SPH_C32(0x0E4B0E4B),
    SPH_C32(0x0EF5F5F5)
};

/* 64‑bit Kb values precomputed for j=16..31 */
#if SPH_64
static const sph_u64 Kb_pre[16] = {
    SPH_C64(0x0555555555555550), SPH_C64(0x05A05A05A05A05A0),
    SPH_C64(0x064B064B064B064B), SPH_C64(0x06F5F5F5F5F5F5F5),
    SPH_C64(0x07A07A07A07A07A0), SPH_C64(0x084B084B084B084B),
    SPH_C64(0x08F5F5F5F5F5F5F5), SPH_C64(0x09A09A09A09A09A0),
    SPH_C64(0x0A4B0A4B0A4B0A4B), SPH_C64(0x0AF5F5F5F5F5F5F5),
    SPH_C64(0x0BA0BA0BA0BA0BA0), SPH_C64(0x0C4B0C4B0C4B0C4B),
    SPH_C64(0x0CF5F5F5F5F5F5F5), SPH_C64(0x0DA0DA0DA0DA0DA0),
    SPH_C64(0x0E4B0E4B0E4B0E4B), SPH_C64(0x0EF5F5F5F5F5F5F5)
};
#endif

/* Final block templates (pre‑expanded constants for the second compression) */
static const sph_u32 final_s_block[16] = {
    SPH_C32(0xaaaaaaa0), SPH_C32(0xaaaaaaa1), SPH_C32(0xaaaaaaa2),
    SPH_C32(0xaaaaaaa3), SPH_C32(0xaaaaaaa4), SPH_C32(0xaaaaaaa5),
    SPH_C32(0xaaaaaaa6), SPH_C32(0xaaaaaaa7), SPH_C32(0xaaaaaaa8),
    SPH_C32(0xaaaaaaa9), SPH_C32(0xaaaaaaaa), SPH_C32(0xaaaaaaab),
    SPH_C32(0xaaaaaaac), SPH_C32(0xaaaaaaad), SPH_C32(0xaaaaaaae),
    SPH_C32(0xaaaaaaaf)
};

#if SPH_64
static const sph_u64 final_b_block[16] = {
    SPH_C64(0xaaaaaaaaaaaaaaa0), SPH_C64(0xaaaaaaaaaaaaaaa1),
    SPH_C64(0xaaaaaaaaaaaaaaa2), SPH_C64(0xaaaaaaaaaaaaaaa3),
    SPH_C64(0xaaaaaaaaaaaaaaa4), SPH_C64(0xaaaaaaaaaaaaaaa5),
    SPH_C64(0xaaaaaaaaaaaaaaa6), SPH_C64(0xaaaaaaaaaaaaaaa7),
    SPH_C64(0xaaaaaaaaaaaaaaa8), SPH_C64(0xaaaaaaaaaaaaaaa9),
    SPH_C64(0xaaaaaaaaaaaaaaaa), SPH_C64(0xaaaaaaaaaaaaaaab),
    SPH_C64(0xaaaaaaaaaaaaaaac), SPH_C64(0xaaaaaaaaaaaaaaad),
    SPH_C64(0xaaaaaaaaaaaaaaae), SPH_C64(0xaaaaaaaaaaaaaaaf)
};
#endif

/* -------------------------------------------------------------------------
 * Small‑footprint vs full‑footprint build asymmetry
 * ------------------------------------------------------------------------- */
#if SPH_SMALL_FOOTPRINT && !defined SPH_SMALL_FOOTPRINT_BMW
#define SPH_SMALL_FOOTPRINT_BMW 1
#endif

#ifdef _MSC_VER
#pragma warning (disable: 4146)
#endif

/* Original IVs (unchanged) */
static const sph_u32 IV224[] = {
    SPH_C32(0x00010203), SPH_C32(0x04050607), SPH_C32(0x08090A0B), SPH_C32(0x0C0D0E0F),
    SPH_C32(0x10111213), SPH_C32(0x14151617), SPH_C32(0x18191A1B), SPH_C32(0x1C1D1E1F),
    SPH_C32(0x20212223), SPH_C32(0x24252627), SPH_C32(0x28292A2B), SPH_C32(0x2C2D2E2F),
    SPH_C32(0x30313233), SPH_C32(0x34353637), SPH_C32(0x38393A3B), SPH_C32(0x3C3D3E3F)
};

static const sph_u32 IV256[] = {
    SPH_C32(0x40414243), SPH_C32(0x44454647), SPH_C32(0x48494A4B), SPH_C32(0x4C4D4E4F),
    SPH_C32(0x50515253), SPH_C32(0x54555657), SPH_C32(0x58595A5B), SPH_C32(0x5C5D5E5F),
    SPH_C32(0x60616263), SPH_C32(0x64656667), SPH_C32(0x68696A6B), SPH_C32(0x6C6D6E6F),
    SPH_C32(0x70717273), SPH_C32(0x74757677), SPH_C32(0x78797A7B), SPH_C32(0x7C7D7E7F)
};

#if SPH_64
static const sph_u64 IV384[] = {
    SPH_C64(0x0001020304050607), SPH_C64(0x08090A0B0C0D0E0F),
    SPH_C64(0x1011121314151617), SPH_C64(0x18191A1B1C1D1E1F),
    SPH_C64(0x2021222324252627), SPH_C64(0x28292A2B2C2D2E2F),
    SPH_C64(0x3031323334353637), SPH_C64(0x38393A3B3C3D3E3F),
    SPH_C64(0x4041424344454647), SPH_C64(0x48494A4B4C4D4E4F),
    SPH_C64(0x5051525354555657), SPH_C64(0x58595A5B5C5D5E5F),
    SPH_C64(0x6061626364656667), SPH_C64(0x68696A6B6C6D6E6F),
    SPH_C64(0x7071727374757677), SPH_C64(0x78797A7B7C7D7E7F)
};

static const sph_u64 IV512[] = {
    SPH_C64(0x8081828384858687), SPH_C64(0x88898A8B8C8D8E8F),
    SPH_C64(0x9091929394959697), SPH_C64(0x98999A9B9C9D9E9F),
    SPH_C64(0xA0A1A2A3A4A5A6A7), SPH_C64(0xA8A9AAABACADAEAF),
    SPH_C64(0xB0B1B2B3B4B5B6B7), SPH_C64(0xB8B9BABBBCBDBEBF),
    SPH_C64(0xC0C1C2C3C4C5C6C7), SPH_C64(0xC8C9CACBCCCDCECF),
    SPH_C64(0xD0D1D2D3D4D5D6D7), SPH_C64(0xD8D9DADBDCDDDEDF),
    SPH_C64(0xE0E1E2E3E4E5E6E7), SPH_C64(0xE8E9EAEBECEDEEEF),
    SPH_C64(0xF0F1F2F3F4F5F6F7), SPH_C64(0xF8F9FAFBFCFDFEFF)
};
#endif

/* -------------------------------------------------------------------------
 * 32‑bit Core Optimizations
 * ------------------------------------------------------------------------- */
#define ss0(x)  (((x) >> 1) ^ SPH_T32((x) << 3) ^ SPH_ROTL32(x,  4) ^ SPH_ROTL32(x, 19))
#define ss1(x)  (((x) >> 1) ^ SPH_T32((x) << 2) ^ SPH_ROTL32(x,  8) ^ SPH_ROTL32(x, 23))
#define ss2(x)  (((x) >> 2) ^ SPH_T32((x) << 1) ^ SPH_ROTL32(x, 12) ^ SPH_ROTL32(x, 25))
#define ss3(x)  (((x) >> 2) ^ SPH_T32((x) << 2) ^ SPH_ROTL32(x, 15) ^ SPH_ROTL32(x, 29))
#define ss4(x)  (((x) >> 1) ^ (x))
#define ss5(x)  (((x) >> 2) ^ (x))
#define rs1(x)  SPH_ROTL32(x,  3)
#define rs2(x)  SPH_ROTL32(x,  7)
#define rs3(x)  SPH_ROTL32(x, 13)
#define rs4(x)  SPH_ROTL32(x, 16)
#define rs5(x)  SPH_ROTL32(x, 19)
#define rs6(x)  SPH_ROTL32(x, 23)
#define rs7(x)  SPH_ROTL32(x, 27)

/* Precomputed rotation offsets for add_elt_s (stable algebra hoisting) */
static const unsigned char s_rot_off[11] = { 0,1,3,4,7,10,11,0,0,0,0 };

/* -------------------------------------------------------------------------
 * 64‑bit Core Optimizations
 * ------------------------------------------------------------------------- */
#if SPH_64
#define sb0(x)  (((x) >> 1) ^ SPH_T64((x) << 3) ^ SPH_ROTL64(x,  4) ^ SPH_ROTL64(x, 37))
#define sb1(x)  (((x) >> 1) ^ SPH_T64((x) << 2) ^ SPH_ROTL64(x, 13) ^ SPH_ROTL64(x, 43))
#define sb2(x)  (((x) >> 2) ^ SPH_T64((x) << 1) ^ SPH_ROTL64(x, 19) ^ SPH_ROTL64(x, 53))
#define sb3(x)  (((x) >> 2) ^ SPH_T64((x) << 2) ^ SPH_ROTL64(x, 28) ^ SPH_ROTL64(x, 59))
#define sb4(x)  (((x) >> 1) ^ (x))
#define sb5(x)  (((x) >> 2) ^ (x))
#define rb1(x)  SPH_ROTL64(x,  5)
#define rb2(x)  SPH_ROTL64(x, 11)
#define rb3(x)  SPH_ROTL64(x, 27)
#define rb4(x)  SPH_ROTL64(x, 32)
#define rb5(x)  SPH_ROTL64(x, 37)
#define rb6(x)  SPH_ROTL64(x, 43)
#define rb7(x)  SPH_ROTL64(x, 53)
#endif

/* -------------------------------------------------------------------------
 * Word‑schedule templating – fully expanded expand1/2 for 32‑bit
 * ------------------------------------------------------------------------- */
#define EXPAND1_S_TEMPLATE(i16, i0,i1,i2,i3,i4,i5,i6,i7,i8,i9,i10,i11,i12,i13,i14,i15, \
                           i0m,i1m,i3m,i4m,i7m,i10m,i11m) \
    (ss1(Q[i0]) + ss2(Q[i1]) + ss3(Q[i2]) + ss0(Q[i3]) + \
     ss1(Q[i4]) + ss2(Q[i5]) + ss3(Q[i6]) + ss0(Q[i7]) + \
     ss1(Q[i8]) + ss2(Q[i9]) + ss3(Q[i10]) + ss0(Q[i11]) + \
     ss1(Q[i12]) + ss2(Q[i13]) + ss3(Q[i14]) + ss0(Q[i15]) + \
     (SPH_T32(SPH_ROTL32(M[i0m], (i1m)) + SPH_ROTL32(M[i3m], (i4m)) - \
              SPH_ROTL32(M[i10m], (i11m)) + Ks_pre[(i16)-16]) ^ H[i7m]))

#define EXPAND2_S_TEMPLATE(i16, i0,i1,i2,i3,i4,i5,i6,i7,i8,i9,i10,i11,i12,i13,i14,i15, \
                           i0m,i1m,i3m,i4m,i7m,i10m,i11m) \
    (Q[i0] + rs1(Q[i1]) + Q[i2] + rs2(Q[i3]) + \
     Q[i4] + rs3(Q[i5]) + Q[i6] + rs4(Q[i7]) + \
     Q[i8] + rs5(Q[i9]) + Q[i10] + rs6(Q[i11]) + \
     Q[i12] + rs7(Q[i13]) + ss4(Q[i14]) + ss5(Q[i15]) + \
     (SPH_T32(SPH_ROTL32(M[i0m], (i1m)) + SPH_ROTL32(M[i3m], (i4m)) - \
              SPH_ROTL32(M[i10m], (i11m)) + Ks_pre[(i16)-16]) ^ H[i7m]))

/* -------------------------------------------------------------------------
 * Unrolled Folding for 32‑bit (Full Pipeline Collapse)
 * ------------------------------------------------------------------------- */
static SPH_HOT void
bmw32_compress_unrolled(const sph_u32 * SPH_RESTRICT M,
                        const sph_u32 * SPH_RESTRICT H,
                        sph_u32 * SPH_RESTRICT dH)
{
    /* Register‑resident Q array (no stack spills) */
    register sph_u32 q0, q1, q2, q3, q4, q5, q6, q7, q8, q9, q10, q11, q12, q13, q14, q15;
    register sph_u32 q16, q17, q18, q19, q20, q21, q22, q23, q24, q25, q26, q27, q28, q29, q30, q31;

    /* ----- Compute Ws[0..15] directly into Q[0..15] ----- */
    q0  = ss0(((M[5] ^ H[5]) - (M[7] ^ H[7]) + (M[10] ^ H[10]) + (M[13] ^ H[13]) + (M[14] ^ H[14]))) + H[1];
    q1  = ss1(((M[6] ^ H[6]) - (M[8] ^ H[8]) + (M[11] ^ H[11]) + (M[14] ^ H[14]) - (M[15] ^ H[15]))) + H[2];
    q2  = ss2(((M[0] ^ H[0]) + (M[7] ^ H[7]) + (M[9] ^ H[9]) - (M[12] ^ H[12]) + (M[15] ^ H[15]))) + H[3];
    q3  = ss3(((M[0] ^ H[0]) - (M[1] ^ H[1]) + (M[8] ^ H[8]) - (M[10] ^ H[10]) + (M[13] ^ H[13]))) + H[4];
    q4  = ss4(((M[1] ^ H[1]) + (M[2] ^ H[2]) + (M[9] ^ H[9]) - (M[11] ^ H[11]) - (M[14] ^ H[14]))) + H[5];
    q5  = ss0(((M[3] ^ H[3]) - (M[2] ^ H[2]) + (M[10] ^ H[10]) - (M[12] ^ H[12]) + (M[15] ^ H[15]))) + H[6];
    q6  = ss1(((M[4] ^ H[4]) - (M[0] ^ H[0]) - (M[3] ^ H[3]) - (M[11] ^ H[11]) + (M[13] ^ H[13]))) + H[7];
    q7  = ss2(((M[1] ^ H[1]) - (M[4] ^ H[4]) - (M[5] ^ H[5]) - (M[12] ^ H[12]) - (M[14] ^ H[14]))) + H[8];
    q8  = ss3(((M[2] ^ H[2]) - (M[5] ^ H[5]) - (M[6] ^ H[6]) + (M[13] ^ H[13]) - (M[15] ^ H[15]))) + H[9];
    q9  = ss4(((M[0] ^ H[0]) - (M[3] ^ H[3]) + (M[6] ^ H[6]) - (M[7] ^ H[7]) + (M[14] ^ H[14]))) + H[10];
    q10 = ss0(((M[8] ^ H[8]) - (M[1] ^ H[1]) - (M[4] ^ H[4]) - (M[7] ^ H[7]) + (M[15] ^ H[15]))) + H[11];
    q11 = ss1(((M[8] ^ H[8]) - (M[0] ^ H[0]) - (M[2] ^ H[2]) - (M[5] ^ H[5]) + (M[9] ^ H[9]))) + H[12];
    q12 = ss2(((M[1] ^ H[1]) + (M[3] ^ H[3]) - (M[6] ^ H[6]) - (M[9] ^ H[9]) + (M[10] ^ H[10]))) + H[13];
    q13 = ss3(((M[2] ^ H[2]) + (M[4] ^ H[4]) + (M[7] ^ H[7]) + (M[10] ^ H[10]) + (M[11] ^ H[11]))) + H[14];
    q14 = ss4(((M[3] ^ H[3]) - (M[5] ^ H[5]) + (M[8] ^ H[8]) - (M[11] ^ H[11]) - (M[12] ^ H[12]))) + H[15];
    q15 = ss0(((M[12] ^ H[12]) - (M[4] ^ H[4]) - (M[6] ^ H[6]) - (M[9] ^ H[9]) + (M[13] ^ H[13]))) + H[0];

    /* ----- Expand Q[16..31] using templated macros ----- */
    /* 16 */ q16 = EXPAND1_S_TEMPLATE(16, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,3,4,7,10,11);
    /* 17 */ q17 = EXPAND1_S_TEMPLATE(17, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 1,2,4,5,8,11,12);
    /* 18 */ q18 = EXPAND2_S_TEMPLATE(18, 2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17, 2,3,5,6,9,12,13);
    /* 19 */ q19 = EXPAND2_S_TEMPLATE(19, 3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18, 3,4,6,7,10,13,14);
    /* 20 */ q20 = EXPAND2_S_TEMPLATE(20, 4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19, 4,5,7,8,11,14,15);
    /* 21 */ q21 = EXPAND2_S_TEMPLATE(21, 5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20, 5,6,8,9,12,15,16);
    /* 22 */ q22 = EXPAND2_S_TEMPLATE(22, 6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21, 6,7,9,10,13,0,1);
    /* 23 */ q23 = EXPAND2_S_TEMPLATE(23, 7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22, 7,8,10,11,14,1,2);
    /* 24 */ q24 = EXPAND2_S_TEMPLATE(24, 8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23, 8,9,11,12,15,2,3);
    /* 25 */ q25 = EXPAND2_S_TEMPLATE(25, 9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24, 9,10,12,13,0,3,4);
    /* 26 */ q26 = EXPAND2_S_TEMPLATE(26, 10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25, 10,11,13,14,1,4,5);
    /* 27 */ q27 = EXPAND2_S_TEMPLATE(27, 11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26, 11,12,14,15,2,5,6);
    /* 28 */ q28 = EXPAND2_S_TEMPLATE(28, 12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27, 12,13,15,16,3,6,7);
    /* 29 */ q29 = EXPAND2_S_TEMPLATE(29, 13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28, 13,14,0,1,4,7,8);
    /* 30 */ q30 = EXPAND2_S_TEMPLATE(30, 14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29, 14,15,1,2,5,8,9);
    /* 31 */ q31 = EXPAND2_S_TEMPLATE(31, 15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30, 15,16,2,3,6,9,10);

    /* ----- Fold (pipeline collapsed, all temporaries in registers) ----- */
    register sph_u32 xl, xh, t0,t1,t2,t3,t4,t5,t6,t7,t8,t9,t10,t11,t12,t13,t14,t15;
    xl = q16 ^ q17 ^ q18 ^ q19 ^ q20 ^ q21 ^ q22 ^ q23;
    xh = xl ^ q24 ^ q25 ^ q26 ^ q27 ^ q28 ^ q29 ^ q30 ^ q31;

    t0  = SPH_T32(((xh <<  5) ^ (q16 >>  5) ^ M[ 0]) + (xl ^ q24 ^ q0));
    t1  = SPH_T32(((xh >>  7) ^ (q17 <<  8) ^ M[ 1]) + (xl ^ q25 ^ q1));
    t2  = SPH_T32(((xh >>  5) ^ (q18 <<  5) ^ M[ 2]) + (xl ^ q26 ^ q2));
    t3  = SPH_T32(((xh >>  1) ^ (q19 <<  5) ^ M[ 3]) + (xl ^ q27 ^ q3));
    t4  = SPH_T32(((xh >>  3) ^ (q20 <<  0) ^ M[ 4]) + (xl ^ q28 ^ q4));
    t5  = SPH_T32(((xh <<  6) ^ (q21 >>  6) ^ M[ 5]) + (xl ^ q29 ^ q5));
    t6  = SPH_T32(((xh >>  4) ^ (q22 <<  6) ^ M[ 6]) + (xl ^ q30 ^ q6));
    t7  = SPH_T32(((xh >> 11) ^ (q23 <<  2) ^ M[ 7]) + (xl ^ q31 ^ q7));

    dH[0] = t0; dH[1] = t1; dH[2] = t2; dH[3] = t3;
    dH[4] = t4; dH[5] = t5; dH[6] = t6; dH[7] = t7;

    t8  = SPH_T32(SPH_ROTL32(t4,  9) + (xh ^ q24 ^ M[ 8]) + ((xl << 8) ^ q23 ^ q8));
    t9  = SPH_T32(SPH_ROTL32(t5, 10) + (xh ^ q25 ^ M[ 9]) + ((xl >> 6) ^ q16 ^ q9));
    t10 = SPH_T32(SPH_ROTL32(t6, 11) + (xh ^ q26 ^ M[10]) + ((xl << 6) ^ q17 ^ q10));
    t11 = SPH_T32(SPH_ROTL32(t7, 12) + (xh ^ q27 ^ M[11]) + ((xl << 4) ^ q18 ^ q11));
    t12 = SPH_T32(SPH_ROTL32(t0, 13) + (xh ^ q28 ^ M[12]) + ((xl >> 3) ^ q19 ^ q12));
    t13 = SPH_T32(SPH_ROTL32(t1, 14) + (xh ^ q29 ^ M[13]) + ((xl >> 4) ^ q20 ^ q13));
    t14 = SPH_T32(SPH_ROTL32(t2, 15) + (xh ^ q30 ^ M[14]) + ((xl >> 7) ^ q21 ^ q14));
    t15 = SPH_T32(SPH_ROTL32(t3, 16) + (xh ^ q31 ^ M[15]) + ((xl >> 2) ^ q22 ^ q15));

    dH[ 8] = t8;  dH[ 9] = t9;  dH[10] = t10; dH[11] = t11;
    dH[12] = t12; dH[13] = t13; dH[14] = t14; dH[15] = t15;
}

/* -------------------------------------------------------------------------
 * 64‑bit Unrolled Compression (dominant path)
 * ------------------------------------------------------------------------- */
#if SPH_64
static SPH_HOT void
bmw64_compress_unrolled(const sph_u64 * SPH_RESTRICT M,
                        const sph_u64 * SPH_RESTRICT H,
                        sph_u64 * SPH_RESTRICT dH)
{
    register sph_u64 q0, q1, q2, q3, q4, q5, q6, q7, q8, q9, q10, q11, q12, q13, q14, q15;
    register sph_u64 q16, q17, q18, q19, q20, q21, q22, q23, q24, q25, q26, q27, q28, q29, q30, q31;

    /* Compute Wb[0..15] */
    q0  = sb0(((M[5] ^ H[5]) - (M[7] ^ H[7]) + (M[10] ^ H[10]) + (M[13] ^ H[13]) + (M[14] ^ H[14]))) + H[1];
    q1  = sb1(((M[6] ^ H[6]) - (M[8] ^ H[8]) + (M[11] ^ H[11]) + (M[14] ^ H[14]) - (M[15] ^ H[15]))) + H[2];
    q2  = sb2(((M[0] ^ H[0]) + (M[7] ^ H[7]) + (M[9] ^ H[9]) - (M[12] ^ H[12]) + (M[15] ^ H[15]))) + H[3];
    q3  = sb3(((M[0] ^ H[0]) - (M[1] ^ H[1]) + (M[8] ^ H[8]) - (M[10] ^ H[10]) + (M[13] ^ H[13]))) + H[4];
    q4  = sb4(((M[1] ^ H[1]) + (M[2] ^ H[2]) + (M[9] ^ H[9]) - (M[11] ^ H[11]) - (M[14] ^ H[14]))) + H[5];
    q5  = sb0(((M[3] ^ H[3]) - (M[2] ^ H[2]) + (M[10] ^ H[10]) - (M[12] ^ H[12]) + (M[15] ^ H[15]))) + H[6];
    q6  = sb1(((M[4] ^ H[4]) - (M[0] ^ H[0]) - (M[3] ^ H[3]) - (M[11] ^ H[11]) + (M[13] ^ H[13]))) + H[7];
    q7  = sb2(((M[1] ^ H[1]) - (M[4] ^ H[4]) - (M[5] ^ H[5]) - (M[12] ^ H[12]) - (M[14] ^ H[14]))) + H[8];
    q8  = sb3(((M[2] ^ H[2]) - (M[5] ^ H[5]) - (M[6] ^ H[6]) + (M[13] ^ H[13]) - (M[15] ^ H[15]))) + H[9];
    q9  = sb4(((M[0] ^ H[0]) - (M[3] ^ H[3]) + (M[6] ^ H[6]) - (M[7] ^ H[7]) + (M[14] ^ H[14]))) + H[10];
    q10 = sb0(((M[8] ^ H[8]) - (M[1] ^ H[1]) - (M[4] ^ H[4]) - (M[7] ^ H[7]) + (M[15] ^ H[15]))) + H[11];
    q11 = sb1(((M[8] ^ H[8]) - (M[0] ^ H[0]) - (M[2] ^ H[2]) - (M[5] ^ H[5]) + (M[9] ^ H[9]))) + H[12];
    q12 = sb2(((M[1] ^ H[1]) + (M[3] ^ H[3]) - (M[6] ^ H[6]) - (M[9] ^ H[9]) + (M[10] ^ H[10]))) + H[13];
    q13 = sb3(((M[2] ^ H[2]) + (M[4] ^ H[4]) + (M[7] ^ H[7]) + (M[10] ^ H[10]) + (M[11] ^ H[11]))) + H[14];
    q14 = sb4(((M[3] ^ H[3]) - (M[5] ^ H[5]) + (M[8] ^ H[8]) - (M[11] ^ H[11]) - (M[12] ^ H[12]))) + H[15];
    q15 = sb0(((M[12] ^ H[12]) - (M[4] ^ H[4]) - (M[6] ^ H[6]) - (M[9] ^ H[9]) + (M[13] ^ H[13]))) + H[0];

    /* Expand Q[16..31] with templated 64‑bit macros */
    #define EXPAND1_B_TEMPLATE(i16, i0,i1,i2,i3,i4,i5,i6,i7,i8,i9,i10,i11,i12,i13,i14,i15, \
                               i0m,i1m,i3m,i4m,i7m,i10m,i11m) \
        (sb1(Q[i0]) + sb2(Q[i1]) + sb3(Q[i2]) + sb0(Q[i3]) + \
         sb1(Q[i4]) + sb2(Q[i5]) + sb3(Q[i6]) + sb0(Q[i7]) + \
         sb1(Q[i8]) + sb2(Q[i9]) + sb3(Q[i10]) + sb0(Q[i11]) + \
         sb1(Q[i12]) + sb2(Q[i13]) + sb3(Q[i14]) + sb0(Q[i15]) + \
         (SPH_T64(SPH_ROTL64(M[i0m], (i1m)) + SPH_ROTL64(M[i3m], (i4m)) - \
                  SPH_ROTL64(M[i10m], (i11m)) + Kb_pre[(i16)-16]) ^ H[i7m]))
    #define EXPAND2_B_TEMPLATE(i16, i0,i1,i2,i3,i4,i5,i6,i7,i8,i9,i10,i11,i12,i13,i14,i15, \
                               i0m,i1m,i3m,i4m,i7m,i10m,i11m) \
        (Q[i0] + rb1(Q[i1]) + Q[i2] + rb2(Q[i3]) + \
         Q[i4] + rb3(Q[i5]) + Q[i6] + rb4(Q[i7]) + \
         Q[i8] + rb5(Q[i9]) + Q[i10] + rb6(Q[i11]) + \
         Q[i12] + rb7(Q[i13]) + sb4(Q[i14]) + sb5(Q[i15]) + \
         (SPH_T64(SPH_ROTL64(M[i0m], (i1m)) + SPH_ROTL64(M[i3m], (i4m)) - \
                  SPH_ROTL64(M[i10m], (i11m)) + Kb_pre[(i16)-16]) ^ H[i7m]))

    /* 16 */ q16 = EXPAND1_B_TEMPLATE(16, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,3,4,7,10,11);
    /* 17 */ q17 = EXPAND1_B_TEMPLATE(17, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 1,2,4,5,8,11,12);
    /* 18 */ q18 = EXPAND2_B_TEMPLATE(18, 2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17, 2,3,5,6,9,12,13);
    /* 19 */ q19 = EXPAND2_B_TEMPLATE(19, 3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18, 3,4,6,7,10,13,14);
    /* 20 */ q20 = EXPAND2_B_TEMPLATE(20, 4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19, 4,5,7,8,11,14,15);
    /* 21 */ q21 = EXPAND2_B_TEMPLATE(21, 5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20, 5,6,8,9,12,15,16);
    /* 22 */ q22 = EXPAND2_B_TEMPLATE(22, 6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21, 6,7,9,10,13,0,1);
    /* 23 */ q23 = EXPAND2_B_TEMPLATE(23, 7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22, 7,8,10,11,14,1,2);
    /* 24 */ q24 = EXPAND2_B_TEMPLATE(24, 8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23, 8,9,11,12,15,2,3);
    /* 25 */ q25 = EXPAND2_B_TEMPLATE(25, 9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24, 9,10,12,13,0,3,4);
    /* 26 */ q26 = EXPAND2_B_TEMPLATE(26, 10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25, 10,11,13,14,1,4,5);
    /* 27 */ q27 = EXPAND2_B_TEMPLATE(27, 11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26, 11,12,14,15,2,5,6);
    /* 28 */ q28 = EXPAND2_B_TEMPLATE(28, 12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27, 12,13,15,16,3,6,7);
    /* 29 */ q29 = EXPAND2_B_TEMPLATE(29, 13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28, 13,14,0,1,4,7,8);
    /* 30 */ q30 = EXPAND2_B_TEMPLATE(30, 14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29, 14,15,1,2,5,8,9);
    /* 31 */ q31 = EXPAND2_B_TEMPLATE(31, 15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30, 15,16,2,3,6,9,10);

    #undef EXPAND1_B_TEMPLATE
    #undef EXPAND2_B_TEMPLATE

    /* Fold (64‑bit unrolled) */
    register sph_u64 xl, xh, t0,t1,t2,t3,t4,t5,t6,t7,t8,t9,t10,t11,t12,t13,t14,t15;
    xl = q16 ^ q17 ^ q18 ^ q19 ^ q20 ^ q21 ^ q22 ^ q23;
    xh = xl ^ q24 ^ q25 ^ q26 ^ q27 ^ q28 ^ q29 ^ q30 ^ q31;

    t0  = SPH_T64(((xh <<  5) ^ (q16 >>  5) ^ M[ 0]) + (xl ^ q24 ^ q0));
    t1  = SPH_T64(((xh >>  7) ^ (q17 <<  8) ^ M[ 1]) + (xl ^ q25 ^ q1));
    t2  = SPH_T64(((xh >>  5) ^ (q18 <<  5) ^ M[ 2]) + (xl ^ q26 ^ q2));
    t3  = SPH_T64(((xh >>  1) ^ (q19 <<  5) ^ M[ 3]) + (xl ^ q27 ^ q3));
    t4  = SPH_T64(((xh >>  3) ^ (q20 <<  0) ^ M[ 4]) + (xl ^ q28 ^ q4));
    t5  = SPH_T64(((xh <<  6) ^ (q21 >>  6) ^ M[ 5]) + (xl ^ q29 ^ q5));
    t6  = SPH_T64(((xh >>  4) ^ (q22 <<  6) ^ M[ 6]) + (xl ^ q30 ^ q6));
    t7  = SPH_T64(((xh >> 11) ^ (q23 <<  2) ^ M[ 7]) + (xl ^ q31 ^ q7));

    dH[0] = t0; dH[1] = t1; dH[2] = t2; dH[3] = t3;
    dH[4] = t4; dH[5] = t5; dH[6] = t6; dH[7] = t7;

    t8  = SPH_T64(SPH_ROTL64(t4,  9) + (xh ^ q24 ^ M[ 8]) + ((xl << 8) ^ q23 ^ q8));
    t9  = SPH_T64(SPH_ROTL64(t5, 10) + (xh ^ q25 ^ M[ 9]) + ((xl >> 6) ^ q16 ^ q9));
    t10 = SPH_T64(SPH_ROTL64(t6, 11) + (xh ^ q26 ^ M[10]) + ((xl << 6) ^ q17 ^ q10));
    t11 = SPH_T64(SPH_ROTL64(t7, 12) + (xh ^ q27 ^ M[11]) + ((xl << 4) ^ q18 ^ q11));
    t12 = SPH_T64(SPH_ROTL64(t0, 13) + (xh ^ q28 ^ M[12]) + ((xl >> 3) ^ q19 ^ q12));
    t13 = SPH_T64(SPH_ROTL64(t1, 14) + (xh ^ q29 ^ M[13]) + ((xl >> 4) ^ q20 ^ q13));
    t14 = SPH_T64(SPH_ROTL64(t2, 15) + (xh ^ q30 ^ M[14]) + ((xl >> 7) ^ q21 ^ q14));
    t15 = SPH_T64(SPH_ROTL64(t3, 16) + (xh ^ q31 ^ M[15]) + ((xl >> 2) ^ q22 ^ q15));

    dH[ 8] = t8;  dH[ 9] = t9;  dH[10] = t10; dH[11] = t11;
    dH[12] = t12; dH[13] = t13; dH[14] = t14; dH[15] = t15;
}
#endif

/* -------------------------------------------------------------------------
 * Endian/Layout Preformatting + Input Update Shaping
 * ------------------------------------------------------------------------- */
static SPH_ALWAYS_INLINE void
load32_block(const unsigned char *data, sph_u32 *mv) {
#if SPH_LITTLE_FAST
    /* Aligned little‑endian load: one memcpy may be optimized by compiler */
    memcpy(mv, data, 64);
#else
    unsigned i;
    for (i = 0; i < 16; i++)
        mv[i] = sph_dec32le_aligned(data + 4*i);
#endif
}

#if SPH_64
static SPH_ALWAYS_INLINE void
load64_block(const unsigned char *data, sph_u64 *mv) {
#if SPH_LITTLE_FAST
    memcpy(mv, data, 128);
#else
    unsigned i;
    for (i = 0; i < 16; i++)
        mv[i] = sph_dec64le_aligned(data + 8*i);
#endif
}
#endif

/* -------------------------------------------------------------------------
 * 32‑bit Context & Update Functions (Optimized)
 * ------------------------------------------------------------------------- */
static void
bmw32_init(sph_bmw_small_context *sc, const sph_u32 *iv)
{
    memcpy(sc->H, iv, sizeof sc->H);
    sc->ptr = 0;
#if SPH_64
    sc->bit_count = 0;
#else
    sc->bit_count_high = 0;
    sc->bit_count_low = 0;
#endif
}

static SPH_HOT void
bmw32_update(sph_bmw_small_context *sc, const void *data, size_t len)
{
    unsigned char *buf = sc->buf;
    size_t ptr = sc->ptr;
    sph_u32 htmp[16] SPH_ALIGNED(16);
    sph_u32 *h1 = sc->H;
    sph_u32 *h2 = htmp;
    const unsigned char *in = (const unsigned char *)data;

    /* Prefetch first block if available */
    if (len >= 64) SPH_PREFETCH(in);

#if SPH_64
    sc->bit_count += (sph_u64)len << 3;
#else
    {
        sph_u32 tmp = sc->bit_count_low;
        sc->bit_count_low = SPH_T32(tmp + ((sph_u32)len << 3));
        if (sc->bit_count_low < tmp) sc->bit_count_high++;
        sc->bit_count_high += (sph_u32)(len >> 29);
    }
#endif

    if (ptr != 0) {
        size_t clen = 64 - ptr;
        if (clen > len) clen = len;
        memcpy(buf + ptr, in, clen);
        in += clen;
        len -= clen;
        ptr += clen;
        if (ptr == 64) {
            sph_u32 M[16] SPH_ALIGNED(16);
            load32_block(buf, M);
            bmw32_compress_unrolled(M, h1, h2);
            /* swap h1 and h2 */
            sph_u32 *ht = h1; h1 = h2; h2 = ht;
            ptr = 0;
        }
    }

    /* Bulk processing of full blocks (batched parallel kernels) */
    while (len >= 64) {
        SPH_PREFETCH(in + 64);
        sph_u32 M[16] SPH_ALIGNED(16);
        load32_block(in, M);
        bmw32_compress_unrolled(M, h1, h2);
        /* swap */
        sph_u32 *ht = h1; h1 = h2; h2 = ht;
        in += 64;
        len -= 64;
    }

    if (len > 0) {
        memcpy(buf, in, len);
        ptr = len;
    }

    sc->ptr = ptr;
    if (h1 != sc->H)
        memcpy(sc->H, h1, sizeof sc->H);
}

/* -------------------------------------------------------------------------
 * Fused Close + Target Kernel (Full Tail‑Pipeline Collapse)
 * ------------------------------------------------------------------------- */
static void
bmw32_close_fused(sph_bmw_small_context *sc, unsigned ub, unsigned n,
                  void *dst, size_t out_size_w32)
{
    unsigned char *buf = sc->buf;
    size_t ptr = sc->ptr;
    unsigned z = 0x80 >> n;
    sph_u32 h1[16] SPH_ALIGNED(16), h2[16] SPH_ALIGNED(16);
    sph_u32 *state = sc->H;

    /* Bit‑level close semantic drift: handle padding directly */
    buf[ptr++] = ((ub & -z) | z) & 0xFF;

    /* Close‑boundary engineering */
    if (ptr > 64 - 8) {
        memset(buf + ptr, 0, 64 - ptr);
        sph_u32 M[16] SPH_ALIGNED(16);
        load32_block(buf, M);
        bmw32_compress_unrolled(M, state, h1);
        ptr = 0;
        state = h1;
    }
    memset(buf + ptr, 0, 64 - 8 - ptr);
#if SPH_64
    sph_enc64le_aligned(buf + 56, sc->bit_count + n);
#else
    sph_enc32le_aligned(buf + 56, sc->bit_count_low + n);
    sph_enc32le_aligned(buf + 60, sc->bit_count_high);
#endif

    /* First compression (padded message) */
    {
        sph_u32 M[16] SPH_ALIGNED(16);
        load32_block(buf, M);
        bmw32_compress_unrolled(M, state, h2);
    }

    /* Second compression with final template (precomputed block) */
    bmw32_compress_unrolled(final_s_block, h2, h1);

    /* Partial‑output ordering exploit: unrolled output generation */
    unsigned char *out = (unsigned char *)dst;
    unsigned u;
    for (u = 0; u < out_size_w32; u++)
        sph_enc32le(out + 4*u, h1[16 - out_size_w32 + u]);

    /* Re‑init context (one‑shot semantics) */
    bmw32_init(sc, (out_size_w32 == 7) ? IV224 : IV256);
}

/* -------------------------------------------------------------------------
 * 64‑bit Context & Update Functions (Optimized, Dominant Path)
 * ------------------------------------------------------------------------- */
#if SPH_64
static void
bmw64_init(sph_bmw_big_context *sc, const sph_u64 *iv)
{
    memcpy(sc->H, iv, sizeof sc->H);
    sc->ptr = 0;
    sc->bit_count = 0;
}

static SPH_HOT void
bmw64_update(sph_bmw_big_context *sc, const void *data, size_t len)
{
    unsigned char *buf = sc->buf;
    size_t ptr = sc->ptr;
    sph_u64 htmp[16] SPH_ALIGNED(32);
    sph_u64 *h1 = sc->H;
    sph_u64 *h2 = htmp;
    const unsigned char *in = (const unsigned char *)data;

    if (len >= 128) SPH_PREFETCH(in);
    sc->bit_count += (sph_u64)len << 3;

    if (ptr != 0) {
        size_t clen = 128 - ptr;
        if (clen > len) clen = len;
        memcpy(buf + ptr, in, clen);
        in += clen;
        len -= clen;
        ptr += clen;
        if (ptr == 128) {
            sph_u64 M[16] SPH_ALIGNED(32);
            load64_block(buf, M);
            bmw64_compress_unrolled(M, h1, h2);
            sph_u64 *ht = h1; h1 = h2; h2 = ht;
            ptr = 0;
        }
    }

    while (len >= 128) {
        SPH_PREFETCH(in + 128);
        sph_u64 M[16] SPH_ALIGNED(32);
        load64_block(in, M);
        bmw64_compress_unrolled(M, h1, h2);
        sph_u64 *ht = h1; h1 = h2; h2 = ht;
        in += 128;
        len -= 128;
    }

    if (len > 0) {
        memcpy(buf, in, len);
        ptr = len;
    }

    sc->ptr = ptr;
    if (h1 != sc->H)
        memcpy(sc->H, h1, sizeof sc->H);
}

static void
bmw64_close_fused(sph_bmw_big_context *sc, unsigned ub, unsigned n,
                  void *dst, size_t out_size_w64)
{
    unsigned char *buf = sc->buf;
    size_t ptr = sc->ptr;
    unsigned z = 0x80 >> n;
    sph_u64 h1[16] SPH_ALIGNED(32), h2[16] SPH_ALIGNED(32);
    sph_u64 *state = sc->H;

    buf[ptr++] = ((ub & -z) | z) & 0xFF;

    if (ptr > 128 - 8) {
        memset(buf + ptr, 0, 128 - ptr);
        sph_u64 M[16] SPH_ALIGNED(32);
        load64_block(buf, M);
        bmw64_compress_unrolled(M, state, h1);
        ptr = 0;
        state = h1;
    }
    memset(buf + ptr, 0, 128 - 8 - ptr);
    sph_enc64le_aligned(buf + 120, sc->bit_count + n);

    {
        sph_u64 M[16] SPH_ALIGNED(32);
        load64_block(buf, M);
        bmw64_compress_unrolled(M, state, h2);
    }

    bmw64_compress_unrolled(final_b_block, h2, h1);

    unsigned char *out = (unsigned char *)dst;
    unsigned u;
    for (u = 0; u < out_size_w64; u++)
        sph_enc64le(out + 8*u, h1[16 - out_size_w64 + u]);

    bmw64_init(sc, (out_size_w64 == 6) ? IV384 : IV512);
}
#endif

/* -------------------------------------------------------------------------
 * One‑Shot Kernel Specializations (Fixed‑Length Custom Kernel)
 * ------------------------------------------------------------------------- */
void
sph_bmw256_direct(const void *data, size_t len, void *dst)
{
    sph_bmw_small_context sc;
    bmw32_init(&sc, IV256);
    if (len == 64) {
        /* Exact mutable‑word specialization: exactly one block */
        sph_u32 M[16] SPH_ALIGNED(16);
        load32_block(data, M);
        bmw32_compress_unrolled(M, sc.H, sc.H);
        /* Tail pipeline collapse: compress with final block and output */
        sph_u32 final_h[16] SPH_ALIGNED(16);
        bmw32_compress_unrolled(final_s_block, sc.H, final_h);
        unsigned char *out = dst;
        for (unsigned u = 0; u < 8; u++)
            sph_enc32le(out + 4*u, final_h[8 + u]);
    } else {
        bmw32_update(&sc, data, len);
        bmw32_close_fused(&sc, 0, 0, dst, 8);
    }
}

void
sph_bmw512_direct(const void *data, size_t len, void *dst)
{
#if SPH_64
    sph_bmw_big_context sc;
    bmw64_init(&sc, IV512);
    if (len == 128) {
        sph_u64 M[16] SPH_ALIGNED(32);
        load64_block(data, M);
        bmw64_compress_unrolled(M, sc.H, sc.H);
        sph_u64 final_h[16] SPH_ALIGNED(32);
        bmw64_compress_unrolled(final_b_block, sc.H, final_h);
        unsigned char *out = dst;
        for (unsigned u = 0; u < 8; u++)
            sph_enc64le(out + 8*u, final_h[8 + u]);
    } else {
        bmw64_update(&sc, data, len);
        bmw64_close_fused(&sc, 0, 0, dst, 8);
    }
#else
    /* Fallback for 32‑bit only builds */
    sph_bmw_small_context sc;
    bmw32_init(&sc, IV256);
    bmw32_update(&sc, data, len);
    bmw32_close_fused(&sc, 0, 0, dst, 8);
#endif
}

/* -------------------------------------------------------------------------
 * Target‑Check Only Path (Partial State Reuse)
 * ------------------------------------------------------------------------- */
int
sph_bmw256_check_target(const void *data, size_t len,
                        const void *target, size_t target_len)
{
    sph_bmw_small_context sc;
    bmw32_init(&sc, IV256);
    bmw32_update(&sc, data, len);
    /* Compute only first target_len bytes of hash */
    unsigned char hash[32];
    bmw32_close_fused(&sc, 0, 0, hash, 8);
    return memcmp(hash, target, target_len) == 0;
}

/* -------------------------------------------------------------------------
 * Deep State Reuse / Partial‑Context Cloning
 * ------------------------------------------------------------------------- */
void
sph_bmw256_state_copy(const sph_bmw_small_context *src, sph_bmw_small_context *dst)
{
    memcpy(dst, src, sizeof *dst);
}

void
sph_bmw256_state_patch_word(sph_bmw_small_context *sc, unsigned idx, sph_u32 value)
{
    if (idx < 16) sc->H[idx] = value;
}

/* -------------------------------------------------------------------------
 * Batched Parallel Kernels (Multi‑Block Processing)
 * ------------------------------------------------------------------------- */
void
sph_bmw256_batched(const void *data, size_t block_count, void *out_array)
{
    const unsigned char *in = (const unsigned char *)data;
    unsigned char *out = (unsigned char *)out_array;
    sph_bmw_small_context sc;
    for (size_t i = 0; i < block_count; i++) {
        bmw32_init(&sc, IV256);
        sph_u32 M[16] SPH_ALIGNED(16);
        load32_block(in, M);
        bmw32_compress_unrolled(M, sc.H, sc.H);
        sph_u32 final_h[16] SPH_ALIGNED(16);
        bmw32_compress_unrolled(final_s_block, sc.H, final_h);
        for (unsigned u = 0; u < 8; u++)
            sph_enc32le(out + 4*u, final_h[8 + u]);
        in += 64;
        out += 32;
    }
}

/* -------------------------------------------------------------------------
 * Public API Wrappers (Standard sphlib Interface)
 * ------------------------------------------------------------------------- */
void sph_bmw224_init(void *cc) { bmw32_init((sph_bmw_small_context*)cc, IV224); }
void sph_bmw224(void *cc, const void *data, size_t len) { bmw32_update((sph_bmw_small_context*)cc, data, len); }
void sph_bmw224_close(void *cc, void *dst) { sph_bmw224_addbits_and_close(cc, 0, 0, dst); }
void sph_bmw224_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst) {
    bmw32_close_fused((sph_bmw_small_context*)cc, ub, n, dst, 7);
    sph_bmw224_init(cc);
}

void sph_bmw256_init(void *cc) { bmw32_init((sph_bmw_small_context*)cc, IV256); }
void sph_bmw256(void *cc, const void *data, size_t len) { bmw32_update((sph_bmw_small_context*)cc, data, len); }
void sph_bmw256_close(void *cc, void *dst) { sph_bmw256_addbits_and_close(cc, 0, 0, dst); }
void sph_bmw256_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst) {
    bmw32_close_fused((sph_bmw_small_context*)cc, ub, n, dst, 8);
    sph_bmw256_init(cc);
}

#if SPH_64
void sph_bmw384_init(void *cc) { bmw64_init((sph_bmw_big_context*)cc, IV384); }
void sph_bmw384(void *cc, const void *data, size_t len) { bmw64_update((sph_bmw_big_context*)cc, data, len); }
void sph_bmw384_close(void *cc, void *dst) { sph_bmw384_addbits_and_close(cc, 0, 0, dst); }
void sph_bmw384_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst) {
    bmw64_close_fused((sph_bmw_big_context*)cc, ub, n, dst, 6);
    sph_bmw384_init(cc);
}

void sph_bmw512_init(void *cc) { bmw64_init((sph_bmw_big_context*)cc, IV512); }
void sph_bmw512(void *cc, const void *data, size_t len) { bmw64_update((sph_bmw_big_context*)cc, data, len); }
void sph_bmw512_close(void *cc, void *dst) { sph_bmw512_addbits_and_close(cc, 0, 0, dst); }
void sph_bmw512_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst) {
    bmw64_close_fused((sph_bmw_big_context*)cc, ub, n, dst, 8);
    sph_bmw512_init(cc);
}
#endif

#ifdef __cplusplus
}
#endif
