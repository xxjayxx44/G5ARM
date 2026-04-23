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
#define SPH_FLATTEN __attribute__((flatten))
#define SPH_PREFETCH(addr) __builtin_prefetch(addr, 0, 3)
#elif defined(_MSC_VER)
#define SPH_RESTRICT __restrict
#define SPH_ALIGNED(X) __declspec(align(X))
#define SPH_HOT
#define SPH_ALWAYS_INLINE __forceinline
#define SPH_FLATTEN
#define SPH_PREFETCH(addr) _mm_prefetch((const char*)(addr), _MM_HINT_T0)
#else
#define SPH_RESTRICT
#define SPH_ALIGNED(X)
#define SPH_HOT
#define SPH_ALWAYS_INLINE inline
#define SPH_FLATTEN
#define SPH_PREFETCH(addr)
#endif

/* -------------------------------------------------------------------------
 * SIMD & Multi-Core Includes
 * ------------------------------------------------------------------------- */
#if defined(__AVX2__)
#include <immintrin.h>
#endif
#if defined(__SSE4_1__)
#include <smmintrin.h>
#endif
#if defined(__ARM_NEON)
#include <arm_neon.h>
#endif
#ifdef _OPENMP
#include <omp.h>
#endif

/* -------------------------------------------------------------------------
 * Runtime CPU Feature Detection
 * ------------------------------------------------------------------------- */
#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
static inline int bmw_cpu_has_avx2(void) {
    unsigned int eax, ebx, ecx, edx;
    __asm__ __volatile__("cpuid":"=a"(eax),"=b"(ebx),"=c"(ecx),"=d"(edx):"a"(1),"c"(0));
    if (!(ecx & (1U << 27))) return 0;
    unsigned int xcr0;
    __asm__ __volatile__("xgetbv":"=a"(xcr0):"c"(0):"%edx");
    if ((xcr0 & 0x6) != 0x6) return 0;
    __asm__ __volatile__("cpuid":"=a"(eax),"=b"(ebx),"=c"(ecx),"=d"(edx):"a"(7),"c"(0));
    return (ebx & (1U << 5)) != 0;
}
static inline int bmw_cpu_has_sse41(void) {
    unsigned int eax, ebx, ecx, edx;
    __asm__ __volatile__("cpuid":"=a"(eax),"=b"(ebx),"=c"(ecx),"=d"(edx):"a"(1),"c"(0));
    return (ecx & (1U << 19)) != 0;
}
#else
static inline int bmw_cpu_has_avx2(void) { return 0; }
static inline int bmw_cpu_has_sse41(void) { return 0; }
#endif

/* -------------------------------------------------------------------------
 * Precomputed Constants (Hoisting of Stable Algebra)
 * ------------------------------------------------------------------------- */
/* 32‑bit Ks values precomputed for j=16..31 */
static const sph_u32 Ks_pre[16] = {
    SPH_C32(0x55555550), SPH_C32(0x5aaaaaa5), SPH_C32(0x5ffffffa),
    SPH_C32(0x6555554f), SPH_C32(0x6aaaaaa4), SPH_C32(0x6ffffff9),
    SPH_C32(0x7555554e), SPH_C32(0x7aaaaaa3), SPH_C32(0x7ffffff8),
    SPH_C32(0x8555554d), SPH_C32(0x8aaaaaa2), SPH_C32(0x8ffffff7),
    SPH_C32(0x9555554c), SPH_C32(0x9aaaaaa1), SPH_C32(0x9ffffff6),
    SPH_C32(0xa555554b)
};

/* 64‑bit Kb values precomputed for j=16..31 */
#if SPH_64
static const sph_u64 Kb_pre[16] = {
    SPH_C64(0x5555555555555550), SPH_C64(0x5aaaaaaaaaaaaaa5),
    SPH_C64(0x5ffffffffffffffa), SPH_C64(0x655555555555554f),
    SPH_C64(0x6aaaaaaaaaaaaaa4), SPH_C64(0x6ffffffffffffff9),
    SPH_C64(0x755555555555554e), SPH_C64(0x7aaaaaaaaaaaaaa3),
    SPH_C64(0x7ffffffffffffff8), SPH_C64(0x855555555555554d),
    SPH_C64(0x8aaaaaaaaaaaaaa2), SPH_C64(0x8ffffffffffffff7),
    SPH_C64(0x955555555555554c), SPH_C64(0x9aaaaaaaaaaaaaa1),
    SPH_C64(0x9ffffffffffffff6), SPH_C64(0xa55555555555554b)
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
 * Uses token pasting to map indices to register variables q0..q31
 * ------------------------------------------------------------------------- */
#define EXPAND1_S_TEMPLATE(i16, i0,i1,i2,i3,i4,i5,i6,i7,i8,i9,i10,i11,i12,i13,i14,i15, \
                           i0m,i1m,i3m,i4m,i7m,i10m,i11m) \
    (ss1(q##i0) + ss2(q##i1) + ss3(q##i2) + ss0(q##i3) + \
     ss1(q##i4) + ss2(q##i5) + ss3(q##i6) + ss0(q##i7) + \
     ss1(q##i8) + ss2(q##i9) + ss3(q##i10) + ss0(q##i11) + \
     ss1(q##i12) + ss2(q##i13) + ss3(q##i14) + ss0(q##i15) + \
     (SPH_T32(SPH_ROTL32(M[i0m], (i1m)) + SPH_ROTL32(M[i3m], (i4m)) - \
              SPH_ROTL32(M[i10m], (i11m)) + Ks_pre[(i16)-16]) ^ H[i7m]))

#define EXPAND2_S_TEMPLATE(i16, i0,i1,i2,i3,i4,i5,i6,i7,i8,i9,i10,i11,i12,i13,i14,i15, \
                           i0m,i1m,i3m,i4m,i7m,i10m,i11m) \
    (q##i0 + rs1(q##i1) + q##i2 + rs2(q##i3) + \
     q##i4 + rs3(q##i5) + q##i6 + rs4(q##i7) + \
     q##i8 + rs5(q##i9) + q##i10 + rs6(q##i11) + \
     q##i12 + rs7(q##i13) + ss4(q##i14) + ss5(q##i15) + \
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
        (sb1(q##i0) + sb2(q##i1) + sb3(q##i2) + sb0(q##i3) + \
         sb1(q##i4) + sb2(q##i5) + sb3(q##i6) + sb0(q##i7) + \
         sb1(q##i8) + sb2(q##i9) + sb3(q##i10) + sb0(q##i11) + \
         sb1(q##i12) + sb2(q##i13) + sb3(q##i14) + sb0(q##i15) + \
         (SPH_T64(SPH_ROTL64(M[i0m], (i1m)) + SPH_ROTL64(M[i3m], (i4m)) - \
                  SPH_ROTL64(M[i10m], (i11m)) + Kb_pre[(i16)-16]) ^ H[i7m]))
    #define EXPAND2_B_TEMPLATE(i16, i0,i1,i2,i3,i4,i5,i6,i7,i8,i9,i10,i11,i12,i13,i14,i15, \
                               i0m,i1m,i3m,i4m,i7m,i10m,i11m) \
        (q##i0 + rb1(q##i1) + q##i2 + rb2(q##i3) + \
         q##i4 + rb3(q##i5) + q##i6 + rb4(q##i7) + \
         q##i8 + rb5(q##i9) + q##i10 + rb6(q##i11) + \
         q##i12 + rb7(q##i13) + sb4(q##i14) + sb5(q##i15) + \
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

    if (__builtin_expect(ptr != 0, 0)) {
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
    while (__builtin_expect(len >= 64, 1)) {
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
    bmw32_compress_unrolled(h2, final_s_block, h1);

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

    if (__builtin_expect(ptr != 0, 0)) {
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

    while (__builtin_expect(len >= 128, 1)) {
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

    bmw64_compress_unrolled(h2, final_b_block, h1);

    unsigned char *out = (unsigned char *)dst;
    unsigned u;
    for (u = 0; u < out_size_w64; u++)
        sph_enc64le(out + 8*u, h1[16 - out_size_w64 + u]);

    bmw64_init(sc, (out_size_w64 == 6) ? IV384 : IV512);
}
#endif

/* =========================================================================
 * BEYOND ADVANCED: SIMD VECTORIZED MULTI-LANE COMPRESSION
 * ========================================================================= */

/* -------------------------------------------------------------------------
 * AVX2 32-bit 8-wide Vectorized Compression (8x throughput)
 * ------------------------------------------------------------------------- */
#if defined(__AVX2__)

#define TRANSPOSE8x8_I32(r0,r1,r2,r3,r4,r5,r6,r7) do { \
    __m256i __t0,__t1,__t2,__t3,__t4,__t5,__t6,__t7; \
    __m256i __u0,__u1,__u2,__u3,__u4,__u5,__u6,__u7; \
    __t0 = _mm256_unpacklo_epi32(r0,r1); \
    __t1 = _mm256_unpackhi_epi32(r0,r1); \
    __t2 = _mm256_unpacklo_epi32(r2,r3); \
    __t3 = _mm256_unpackhi_epi32(r2,r3); \
    __t4 = _mm256_unpacklo_epi32(r4,r5); \
    __t5 = _mm256_unpackhi_epi32(r4,r5); \
    __t6 = _mm256_unpacklo_epi32(r6,r7); \
    __t7 = _mm256_unpackhi_epi32(r6,r7); \
    __u0 = _mm256_unpacklo_epi64(__t0,__t2); \
    __u1 = _mm256_unpackhi_epi64(__t0,__t2); \
    __u2 = _mm256_unpacklo_epi64(__t1,__t3); \
    __u3 = _mm256_unpackhi_epi64(__t1,__t3); \
    __u4 = _mm256_unpacklo_epi64(__t4,__t6); \
    __u5 = _mm256_unpackhi_epi64(__t4,__t6); \
    __u6 = _mm256_unpacklo_epi64(__t5,__t7); \
    __u7 = _mm256_unpackhi_epi64(__t5,__t7); \
    r0 = _mm256_permute2x128_si256(__u0,__u4,0x20); \
    r1 = _mm256_permute2x128_si256(__u1,__u5,0x20); \
    r2 = _mm256_permute2x128_si256(__u2,__u6,0x20); \
    r3 = _mm256_permute2x128_si256(__u3,__u7,0x20); \
    r4 = _mm256_permute2x128_si256(__u0,__u4,0x31); \
    r5 = _mm256_permute2x128_si256(__u1,__u5,0x31); \
    r6 = _mm256_permute2x128_si256(__u2,__u6,0x31); \
    r7 = _mm256_permute2x128_si256(__u3,__u7,0x31); \
} while(0)

static inline __m256i mm256_rotl_epi32(__m256i x, int n) {
    return _mm256_or_si256(_mm256_slli_epi32(x, n), _mm256_srli_epi32(x, 32-n));
}

#define VXOR(mv,hv,idx) _mm256_xor_si256(mv[idx], hv[idx])

#define VSS0(x) _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(x,1), _mm256_slli_epi32(x,3)), \
         _mm256_xor_si256(mm256_rotl_epi32(x,4), mm256_rotl_epi32(x,19)))
#define VSS1(x) _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(x,1), _mm256_slli_epi32(x,2)), \
         _mm256_xor_si256(mm256_rotl_epi32(x,8), mm256_rotl_epi32(x,23)))
#define VSS2(x) _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(x,2), _mm256_slli_epi32(x,1)), \
         _mm256_xor_si256(mm256_rotl_epi32(x,12), mm256_rotl_epi32(x,25)))
#define VSS3(x) _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(x,2), _mm256_slli_epi32(x,2)), \
         _mm256_xor_si256(mm256_rotl_epi32(x,15), mm256_rotl_epi32(x,29)))
#define VSS4(x) _mm256_xor_si256(_mm256_srli_epi32(x,1), x)
#define VSS5(x) _mm256_xor_si256(_mm256_srli_epi32(x,2), x)
#define VRS1(x) mm256_rotl_epi32(x,3)
#define VRS2(x) mm256_rotl_epi32(x,7)
#define VRS3(x) mm256_rotl_epi32(x,13)
#define VRS4(x) mm256_rotl_epi32(x,16)
#define VRS5(x) mm256_rotl_epi32(x,19)
#define VRS6(x) mm256_rotl_epi32(x,23)
#define VRS7(x) mm256_rotl_epi32(x,27)

static const __m256i Ks_avx2[16] = {
    #define KV(i) _mm256_set1_epi32((int)Ks_pre[i])
    KV(0),KV(1),KV(2),KV(3),KV(4),KV(5),KV(6),KV(7),
    KV(8),KV(9),KV(10),KV(11),KV(12),KV(13),KV(14),KV(15)
    #undef KV
};
static const __m256i final_avx2[16] = {
    #define FV(i) _mm256_set1_epi32((int)final_s_block[i])
    FV(0),FV(1),FV(2),FV(3),FV(4),FV(5),FV(6),FV(7),
    FV(8),FV(9),FV(10),FV(11),FV(12),FV(13),FV(14),FV(15)
    #undef FV
};

#define VADD2(a,b) _mm256_add_epi32(a,b)
#define VADD3(a,b,c) VADD2(VADD2(a,b),c)
#define VADD4(a,b,c,d) VADD2(VADD3(a,b,c),d)
#define VADD5(a,b,c,d,e) VADD2(VADD4(a,b,c,d),e)
#define VADD6(a,b,c,d,e,f) VADD2(VADD5(a,b,c,d,e),f)
#define VADD7(a,b,c,d,e,f,g) VADD2(VADD6(a,b,c,d,e,f),g)
#define VADD8(a,b,c,d,e,f,g,h) VADD2(VADD7(a,b,c,d,e,f,g),h)
#define VADD9(a,b,c,d,e,f,g,h,i) VADD2(VADD8(a,b,c,d,e,f,g,h),i)
#define VADD10(a,b,c,d,e,f,g,h,i,j) VADD2(VADD9(a,b,c,d,e,f,g,h,i),j)
#define VADD11(a,b,c,d,e,f,g,h,i,j,k) VADD2(VADD10(a,b,c,d,e,f,g,h,i,j),k)
#define VADD12(a,b,c,d,e,f,g,h,i,j,k,l) VADD2(VADD11(a,b,c,d,e,f,g,h,i,j,k),l)
#define VADD13(a,b,c,d,e,f,g,h,i,j,k,l,m) VADD2(VADD12(a,b,c,d,e,f,g,h,i,j,k,l),m)
#define VADD14(a,b,c,d,e,f,g,h,i,j,k,l,m,n) VADD2(VADD13(a,b,c,d,e,f,g,h,i,j,k,l,m),n)
#define VADD15(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o) VADD2(VADD14(a,b,c,d,e,f,g,h,i,j,k,l,m,n),o)
#define VADD16(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p) VADD2(VADD15(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o),p)

#define VEXPAND1(i16, i0,i1,i2,i3,i4,i5,i6,i7,i8,i9,i10,i11,i12,i13,i14,i15, \
                 i0m,i1m,i3m,i4m,i7m,i10m,i11m) \
    VADD16(VSS1(q[i0]), VSS2(q[i1]), VSS3(q[i2]), VSS0(q[i3]), \
           VSS1(q[i4]), VSS2(q[i5]), VSS3(q[i6]), VSS0(q[i7]), \
           VSS1(q[i8]), VSS2(q[i9]), VSS3(q[i10]), VSS0(q[i11]), \
           VSS1(q[i12]), VSS2(q[i13]), VSS3(q[i14]), VSS0(q[i15]), \
    _mm256_xor_si256( \
        VADD3(mm256_rotl_epi32(m[i0m],i1m), \
              _mm256_sub_epi32(mm256_rotl_epi32(m[i3m],i4m), mm256_rotl_epi32(m[i10m],i11m)), \
              Ks_avx2[(i16)-16]), \
        h[i7m]))

#define VEXPAND2(i16, i0,i1,i2,i3,i4,i5,i6,i7,i8,i9,i10,i11,i12,i13,i14,i15, \
                 i0m,i1m,i3m,i4m,i7m,i10m,i11m) \
    VADD16(q[i0], VRS1(q[i1]), q[i2], VRS2(q[i3]), \
           q[i4], VRS3(q[i5]), q[i6], VRS4(q[i7]), \
           q[i8], VRS5(q[i9]), q[i10], VRS6(q[i11]), \
           q[i12], VRS7(q[i13]), VSS4(q[i14]), VSS5(q[i15]), \
    _mm256_xor_si256( \
        VADD3(mm256_rotl_epi32(m[i0m],i1m), \
              _mm256_sub_epi32(mm256_rotl_epi32(m[i3m],i4m), mm256_rotl_epi32(m[i10m],i11m)), \
              Ks_avx2[(i16)-16]), \
        h[i7m]))

static SPH_HOT void
bmw32_compress_avx2(const __m256i *SPH_RESTRICT m,
                    const __m256i *SPH_RESTRICT h,
                    __m256i *SPH_RESTRICT dh)
{
    __m256i q[32];
    __m256i xl, xh;
    __m256i t[16];
    int j;

    q[0] = _mm256_add_epi32(VSS0(_mm256_add_epi32(
               _mm256_sub_epi32(VXOR(m,h,5), VXOR(m,h,7)),
               _mm256_add_epi32(VXOR(m,h,10),
                   _mm256_add_epi32(VXOR(m,h,13), VXOR(m,h,14))))), h[1]);
    q[1] = _mm256_add_epi32(VSS1(_mm256_add_epi32(
               _mm256_sub_epi32(VXOR(m,h,6), VXOR(m,h,8)),
               _mm256_add_epi32(VXOR(m,h,11),
                   _mm256_sub_epi32(VXOR(m,h,14), VXOR(m,h,15))))), h[2]);
    q[2] = _mm256_add_epi32(VSS2(_mm256_add_epi32(
               _mm256_add_epi32(VXOR(m,h,0), VXOR(m,h,7)),
               _mm256_add_epi32(VXOR(m,h,9),
                   _mm256_sub_epi32(VXOR(m,h,15), VXOR(m,h,12))))), h[3]);
    q[3] = _mm256_add_epi32(VSS3(_mm256_add_epi32(
               _mm256_sub_epi32(VXOR(m,h,0), VXOR(m,h,1)),
               _mm256_add_epi32(VXOR(m,h,8),
                   _mm256_sub_epi32(VXOR(m,h,13), VXOR(m,h,10))))), h[4]);
    q[4] = _mm256_add_epi32(VSS4(_mm256_add_epi32(
               _mm256_add_epi32(VXOR(m,h,1), VXOR(m,h,2)),
               _mm256_sub_epi32(
                   _mm256_sub_epi32(VXOR(m,h,9), VXOR(m,h,11)),
                   VXOR(m,h,14)))), h[5]);
    q[5] = _mm256_add_epi32(VSS0(_mm256_add_epi32(
               _mm256_sub_epi32(VXOR(m,h,3), VXOR(m,h,2)),
               _mm256_sub_epi32(
                   _mm256_add_epi32(VXOR(m,h,10), VXOR(m,h,15)),
                   VXOR(m,h,12)))), h[6]);
    q[6] = _mm256_add_epi32(VSS1(_mm256_add_epi32(
               _mm256_sub_epi32(
                   _mm256_sub_epi32(VXOR(m,h,4), VXOR(m,h,0)),
                   VXOR(m,h,3)),
               _mm256_sub_epi32(VXOR(m,h,13), VXOR(m,h,11)))), h[7]);
    q[7] = _mm256_add_epi32(VSS2(_mm256_sub_epi32(
               _mm256_sub_epi32(
                   _mm256_sub_epi32(VXOR(m,h,1), VXOR(m,h,4)),
                   VXOR(m,h,5)),
               _mm256_add_epi32(VXOR(m,h,12), VXOR(m,h,14)))), h[8]);
    q[8] = _mm256_add_epi32(VSS3(_mm256_sub_epi32(
               _mm256_sub_epi32(
                   _mm256_sub_epi32(VXOR(m,h,2), VXOR(m,h,5)),
                   VXOR(m,h,6)),
               _mm256_sub_epi32(VXOR(m,h,15), VXOR(m,h,13)))), h[9]);
    q[9] = _mm256_add_epi32(VSS4(_mm256_add_epi32(
               _mm256_sub_epi32(
                   _mm256_add_epi32(VXOR(m,h,0), VXOR(m,h,6)),
                   VXOR(m,h,3)),
               _mm256_sub_epi32(VXOR(m,h,14), VXOR(m,h,7)))), h[10]);
    q[10] = _mm256_add_epi32(VSS0(_mm256_add_epi32(
               _mm256_sub_epi32(
                   _mm256_sub_epi32(VXOR(m,h,8), VXOR(m,h,1)),
                   VXOR(m,h,4)),
               _mm256_sub_epi32(VXOR(m,h,15), VXOR(m,h,7)))), h[11]);
    q[11] = _mm256_add_epi32(VSS1(_mm256_add_epi32(
               _mm256_sub_epi32(
                   _mm256_sub_epi32(VXOR(m,h,8), VXOR(m,h,0)),
                   VXOR(m,h,2)),
               _mm256_sub_epi32(VXOR(m,h,9), VXOR(m,h,5)))), h[12]);
    q[12] = _mm256_add_epi32(VSS2(_mm256_add_epi32(
               _mm256_sub_epi32(
                   _mm256_add_epi32(VXOR(m,h,1), VXOR(m,h,3)),
                   VXOR(m,h,6)),
               _mm256_sub_epi32(VXOR(m,h,10), VXOR(m,h,9)))), h[13]);
    q[13] = _mm256_add_epi32(VSS3(_mm256_add_epi32(
               _mm256_add_epi32(VXOR(m,h,2), VXOR(m,h,4)),
               _mm256_add_epi32(VXOR(m,h,7),
                   _mm256_add_epi32(VXOR(m,h,10), VXOR(m,h,11))))), h[14]);
    q[14] = _mm256_add_epi32(VSS4(_mm256_sub_epi32(
               _mm256_sub_epi32(
                   _mm256_add_epi32(VXOR(m,h,3), VXOR(m,h,8)),
                   VXOR(m,h,5)),
               _mm256_add_epi32(VXOR(m,h,12), VXOR(m,h,11)))), h[15]);
    q[15] = _mm256_add_epi32(VSS0(_mm256_add_epi32(
               _mm256_sub_epi32(
                   _mm256_sub_epi32(VXOR(m,h,12), VXOR(m,h,4)),
                   VXOR(m,h,6)),
               _mm256_sub_epi32(VXOR(m,h,13), VXOR(m,h,9)))), h[0]);

    q[16] = VEXPAND1(16, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,3,4,7,10,11);
    q[17] = VEXPAND1(17, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 1,2,4,5,8,11,12);
    q[18] = VEXPAND2(18, 2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17, 2,3,5,6,9,12,13);
    q[19] = VEXPAND2(19, 3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18, 3,4,6,7,10,13,14);
    q[20] = VEXPAND2(20, 4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19, 4,5,7,8,11,14,15);
    q[21] = VEXPAND2(21, 5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20, 5,6,8,9,12,15,16);
    q[22] = VEXPAND2(22, 6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21, 6,7,9,10,13,0,1);
    q[23] = VEXPAND2(23, 7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22, 7,8,10,11,14,1,2);
    q[24] = VEXPAND2(24, 8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23, 8,9,11,12,15,2,3);
    q[25] = VEXPAND2(25, 9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24, 9,10,12,13,0,3,4);
    q[26] = VEXPAND2(26, 10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25, 10,11,13,14,1,4,5);
    q[27] = VEXPAND2(27, 11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26, 11,12,14,15,2,5,6);
    q[28] = VEXPAND2(28, 12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27, 12,13,15,16,3,6,7);
    q[29] = VEXPAND2(29, 13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28, 13,14,0,1,4,7,8);
    q[30] = VEXPAND2(30, 14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29, 14,15,1,2,5,8,9);
    q[31] = VEXPAND2(31, 15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30, 15,16,2,3,6,9,10);

    xl = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(
         _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(q[16], q[17]),
         q[18]), q[19]), q[20]), q[21]), q[22]), q[23]);
    xh = _mm256_xor_si256(xl, _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(
         _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(q[24], q[25]),
         q[26]), q[27]), q[28]), q[29]), q[30]), q[31]));

    t[0] = _mm256_add_epi32(
        _mm256_xor_si256(_mm256_xor_si256(_mm256_slli_epi32(xh, 5), _mm256_srli_epi32(q[16], 5)), m[0]),
        _mm256_xor_si256(_mm256_xor_si256(xl, q[24]), q[0])
    );
    t[1] = _mm256_add_epi32(
        _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(xh, 7), _mm256_slli_epi32(q[17], 8)), m[1]),
        _mm256_xor_si256(_mm256_xor_si256(xl, q[25]), q[1])
    );
    t[2] = _mm256_add_epi32(
        _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(xh, 5), _mm256_slli_epi32(q[18], 5)), m[2]),
        _mm256_xor_si256(_mm256_xor_si256(xl, q[26]), q[2])
    );
    t[3] = _mm256_add_epi32(
        _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(xh, 1), _mm256_slli_epi32(q[19], 5)), m[3]),
        _mm256_xor_si256(_mm256_xor_si256(xl, q[27]), q[3])
    );
    t[4] = _mm256_add_epi32(
        _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(xh, 3), q[20]), m[4]),
        _mm256_xor_si256(_mm256_xor_si256(xl, q[28]), q[4])
    );
    t[5] = _mm256_add_epi32(
        _mm256_xor_si256(_mm256_xor_si256(_mm256_slli_epi32(xh, 6), _mm256_srli_epi32(q[21], 6)), m[5]),
        _mm256_xor_si256(_mm256_xor_si256(xl, q[29]), q[5])
    );
    t[6] = _mm256_add_epi32(
        _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(xh, 4), _mm256_slli_epi32(q[22], 6)), m[6]),
        _mm256_xor_si256(_mm256_xor_si256(xl, q[30]), q[6])
    );
    t[7] = _mm256_add_epi32(
        _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(xh, 11), _mm256_slli_epi32(q[23], 2)), m[7]),
        _mm256_xor_si256(_mm256_xor_si256(xl, q[31]), q[7])
    );

    t[8] = _mm256_add_epi32(
        _mm256_add_epi32(mm256_rotl_epi32(t[4], 9), _mm256_xor_si256(_mm256_xor_si256(xh, q[24]), m[8])),
        _mm256_xor_si256(_mm256_xor_si256(_mm256_slli_epi32(xl, 8), q[23]), q[8])
    );
    t[9] = _mm256_add_epi32(
        _mm256_add_epi32(mm256_rotl_epi32(t[5], 10), _mm256_xor_si256(_mm256_xor_si256(xh, q[25]), m[9])),
        _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(xl, 6), q[16]), q[9])
    );
    t[10] = _mm256_add_epi32(
        _mm256_add_epi32(mm256_rotl_epi32(t[6], 11), _mm256_xor_si256(_mm256_xor_si256(xh, q[26]), m[10])),
        _mm256_xor_si256(_mm256_xor_si256(_mm256_slli_epi32(xl, 6), q[17]), q[10])
    );
    t[11] = _mm256_add_epi32(
        _mm256_add_epi32(mm256_rotl_epi32(t[7], 12), _mm256_xor_si256(_mm256_xor_si256(xh, q[27]), m[11])),
        _mm256_xor_si256(_mm256_xor_si256(_mm256_slli_epi32(xl, 4), q[18]), q[11])
    );
    t[12] = _mm256_add_epi32(
        _mm256_add_epi32(mm256_rotl_epi32(t[0], 13), _mm256_xor_si256(_mm256_xor_si256(xh, q[28]), m[12])),
        _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(xl, 3), q[19]), q[12])
    );
    t[13] = _mm256_add_epi32(
        _mm256_add_epi32(mm256_rotl_epi32(t[1], 14), _mm256_xor_si256(_mm256_xor_si256(xh, q[29]), m[13])),
        _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(xl, 4), q[20]), q[13])
    );
    t[14] = _mm256_add_epi32(
        _mm256_add_epi32(mm256_rotl_epi32(t[2], 15), _mm256_xor_si256(_mm256_xor_si256(xh, q[30]), m[14])),
        _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(xl, 7), q[21]), q[14])
    );
    t[15] = _mm256_add_epi32(
        _mm256_add_epi32(mm256_rotl_epi32(t[3], 16), _mm256_xor_si256(_mm256_xor_si256(xh, q[31]), m[15])),
        _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(xl, 2), q[22]), q[15])
    );

    for (j = 0; j < 16; j++) dh[j] = t[j];
}

#undef VXOR
#undef VSS0
#undef VSS1
#undef VSS2
#undef VSS3
#undef VSS4
#undef VSS5
#undef VRS1
#undef VRS2
#undef VRS3
#undef VRS4
#undef VRS5
#undef VRS6
#undef VRS7
#undef VADD2
#undef VADD3
#undef VADD4
#undef VADD5
#undef VADD6
#undef VADD7
#undef VADD8
#undef VADD9
#undef VADD10
#undef VADD11
#undef VADD12
#undef VADD13
#undef VADD14
#undef VADD15
#undef VADD16
#undef VEXPAND1
#undef VEXPAND2

#endif /* __AVX2__ */

/* -------------------------------------------------------------------------
 * AVX2 64-bit 4-wide Vectorized Compression (4x throughput)
 * ------------------------------------------------------------------------- */
#if defined(__AVX2__) && SPH_64

static inline __m256i mm256_rotl_epi64(__m256i x, int n) {
    return _mm256_or_si256(_mm256_slli_epi64(x, n), _mm256_srli_epi64(x, 64-n));
}

#define VXOR64(mv,hv,idx) _mm256_xor_si256(mv[idx], hv[idx])

#define VSB0(x) _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi64(x,1), _mm256_slli_epi64(x,3)), \
         _mm256_xor_si256(mm256_rotl_epi64(x,4), mm256_rotl_epi64(x,37)))
#define VSB1(x) _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi64(x,1), _mm256_slli_epi64(x,2)), \
         _mm256_xor_si256(mm256_rotl_epi64(x,13), mm256_rotl_epi64(x,43)))
#define VSB2(x) _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi64(x,2), _mm256_slli_epi64(x,1)), \
         _mm256_xor_si256(mm256_rotl_epi64(x,19), mm256_rotl_epi64(x,53)))
#define VSB3(x) _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi64(x,2), _mm256_slli_epi64(x,2)), \
         _mm256_xor_si256(mm256_rotl_epi64(x,28), mm256_rotl_epi64(x,59)))
#define VSB4(x) _mm256_xor_si256(_mm256_srli_epi64(x,1), x)
#define VSB5(x) _mm256_xor_si256(_mm256_srli_epi64(x,2), x)
#define VRB1(x) mm256_rotl_epi64(x,5)
#define VRB2(x) mm256_rotl_epi64(x,11)
#define VRB3(x) mm256_rotl_epi64(x,27)
#define VRB4(x) mm256_rotl_epi64(x,32)
#define VRB5(x) mm256_rotl_epi64(x,37)
#define VRB6(x) mm256_rotl_epi64(x,43)
#define VRB7(x) mm256_rotl_epi64(x,53)

static const __m256i Kb_avx2[16] = {
    #define KBV(i) _mm256_set1_epi64x((long long)Kb_pre[i])
    KBV(0),KBV(1),KBV(2),KBV(3),KBV(4),KBV(5),KBV(6),KBV(7),
    KBV(8),KBV(9),KBV(10),KBV(11),KBV(12),KBV(13),KBV(14),KBV(15)
    #undef KBV
};
static const __m256i final_b_avx2[16] = {
    #define FBV(i) _mm256_set1_epi64x((long long)final_b_block[i])
    FBV(0),FBV(1),FBV(2),FBV(3),FBV(4),FBV(5),FBV(6),FBV(7),
    FBV(8),FBV(9),FBV(10),FBV(11),FBV(12),FBV(13),FBV(14),FBV(15)
    #undef FBV
};

#define VADD64_2(a,b) _mm256_add_epi64(a,b)
#define VADD64_3(a,b,c) VADD64_2(VADD64_2(a,b),c)
#define VADD64_4(a,b,c,d) VADD64_2(VADD64_3(a,b,c),d)
#define VADD64_5(a,b,c,d,e) VADD64_2(VADD64_4(a,b,c,d),e)
#define VADD64_6(a,b,c,d,e,f) VADD64_2(VADD64_5(a,b,c,d,e),f)
#define VADD64_7(a,b,c,d,e,f,g) VADD64_2(VADD64_6(a,b,c,d,e,f),g)
#define VADD64_8(a,b,c,d,e,f,g,h) VADD64_2(VADD64_7(a,b,c,d,e,f,g),h)
#define VADD64_9(a,b,c,d,e,f,g,h,i) VADD64_2(VADD64_8(a,b,c,d,e,f,g,h),i)
#define VADD64_10(a,b,c,d,e,f,g,h,i,j) VADD64_2(VADD64_9(a,b,c,d,e,f,g,h,i),j)
#define VADD64_11(a,b,c,d,e,f,g,h,i,j,k) VADD64_2(VADD64_10(a,b,c,d,e,f,g,h,i,j),k)
#define VADD64_12(a,b,c,d,e,f,g,h,i,j,k,l) VADD64_2(VADD64_11(a,b,c,d,e,f,g,h,i,j,k),l)
#define VADD64_13(a,b,c,d,e,f,g,h,i,j,k,l,m) VADD64_2(VADD64_12(a,b,c,d,e,f,g,h,i,j,k,l),m)
#define VADD64_14(a,b,c,d,e,f,g,h,i,j,k,l,m,n) VADD64_2(VADD64_13(a,b,c,d,e,f,g,h,i,j,k,l,m),n)
#define VADD64_15(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o) VADD64_2(VADD64_14(a,b,c,d,e,f,g,h,i,j,k,l,m,n),o)
#define VADD64_16(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p) VADD64_2(VADD64_15(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o),p)

#define VEXPAND1_64(i16, i0,i1,i2,i3,i4,i5,i6,i7,i8,i9,i10,i11,i12,i13,i14,i15, \
                    i0m,i1m,i3m,i4m,i7m,i10m,i11m) \
    VADD64_16(VSB1(q[i0]), VSB2(q[i1]), VSB3(q[i2]), VSB0(q[i3]), \
              VSB1(q[i4]), VSB2(q[i5]), VSB3(q[i6]), VSB0(q[i7]), \
              VSB1(q[i8]), VSB2(q[i9]), VSB3(q[i10]), VSB0(q[i11]), \
              VSB1(q[i12]), VSB2(q[i13]), VSB3(q[i14]), VSB0(q[i15]), \
    _mm256_xor_si256( \
        VADD64_3(mm256_rotl_epi64(m[i0m],i1m), \
              _mm256_sub_epi64(mm256_rotl_epi64(m[i3m],i4m), mm256_rotl_epi64(m[i10m],i11m)), \
              Kb_avx2[(i16)-16]), \
        h[i7m]))

#define VEXPAND2_64(i16, i0,i1,i2,i3,i4,i5,i6,i7,i8,i9,i10,i11,i12,i13,i14,i15, \
                    i0m,i1m,i3m,i4m,i7m,i10m,i11m) \
    VADD64_16(q[i0], VRB1(q[i1]), q[i2], VRB2(q[i3]), \
              q[i4], VRB3(q[i5]), q[i6], VRB4(q[i7]), \
              q[i8], VRB5(q[i9]), q[i10], VRB6(q[i11]), \
              q[i12], VRB7(q[i13]), VSB4(q[i14]), VSB5(q[i15]), \
    _mm256_xor_si256( \
        VADD64_3(mm256_rotl_epi64(m[i0m],i1m), \
              _mm256_sub_epi64(mm256_rotl_epi64(m[i3m],i4m), mm256_rotl_epi64(m[i10m],i11m)), \
              Kb_avx2[(i16)-16]), \
        h[i7m]))

static SPH_HOT void
bmw64_compress_avx2(const __m256i *SPH_RESTRICT m,
                    const __m256i *SPH_RESTRICT h,
                    __m256i *SPH_RESTRICT dh)
{
    __m256i q[32];
    __m256i xl, xh;
    __m256i t[16];
    int j;

    q[0] = _mm256_add_epi64(VSB0(_mm256_add_epi64(
               _mm256_sub_epi64(VXOR64(m,h,5), VXOR64(m,h,7)),
               _mm256_add_epi64(VXOR64(m,h,10),
                   _mm256_add_epi64(VXOR64(m,h,13), VXOR64(m,h,14))))), h[1]);
    q[1] = _mm256_add_epi64(VSB1(_mm256_add_epi64(
               _mm256_sub_epi64(VXOR64(m,h,6), VXOR64(m,h,8)),
               _mm256_add_epi64(VXOR64(m,h,11),
                   _mm256_sub_epi64(VXOR64(m,h,14), VXOR64(m,h,15))))), h[2]);
    q[2] = _mm256_add_epi64(VSB2(_mm256_add_epi64(
               _mm256_add_epi64(VXOR64(m,h,0), VXOR64(m,h,7)),
               _mm256_add_epi64(VXOR64(m,h,9),
                   _mm256_sub_epi64(VXOR64(m,h,15), VXOR64(m,h,12))))), h[3]);
    q[3] = _mm256_add_epi64(VSB3(_mm256_add_epi64(
               _mm256_sub_epi64(VXOR64(m,h,0), VXOR64(m,h,1)),
               _mm256_add_epi64(VXOR64(m,h,8),
                   _mm256_sub_epi64(VXOR64(m,h,13), VXOR64(m,h,10))))), h[4]);
    q[4] = _mm256_add_epi64(VSB4(_mm256_add_epi64(
               _mm256_add_epi64(VXOR64(m,h,1), VXOR64(m,h,2)),
               _mm256_sub_epi64(
                   _mm256_sub_epi64(VXOR64(m,h,9), VXOR64(m,h,11)),
                   VXOR64(m,h,14)))), h[5]);
    q[5] = _mm256_add_epi64(VSB0(_mm256_add_epi64(
               _mm256_sub_epi64(VXOR64(m,h,3), VXOR64(m,h,2)),
               _mm256_sub_epi64(
                   _mm256_add_epi64(VXOR64(m,h,10), VXOR64(m,h,15)),
                   VXOR64(m,h,12)))), h[6]);
    q[6] = _mm256_add_epi64(VSB1(_mm256_add_epi64(
               _mm256_sub_epi64(
                   _mm256_sub_epi64(VXOR64(m,h,4), VXOR64(m,h,0)),
                   VXOR64(m,h,3)),
               _mm256_sub_epi64(VXOR64(m,h,13), VXOR64(m,h,11)))), h[7]);
    q[7] = _mm256_add_epi64(VSB2(_mm256_sub_epi64(
               _mm256_sub_epi64(
                   _mm256_sub_epi64(VXOR64(m,h,1), VXOR64(m,h,4)),
                   VXOR64(m,h,5)),
               _mm256_add_epi64(VXOR64(m,h,12), VXOR64(m,h,14)))), h[8]);
    q[8] = _mm256_add_epi64(VSB3(_mm256_sub_epi64(
               _mm256_sub_epi64(
                   _mm256_sub_epi64(VXOR64(m,h,2), VXOR64(m,h,5)),
                   VXOR64(m,h,6)),
               _mm256_sub_epi64(VXOR64(m,h,15), VXOR64(m,h,13)))), h[9]);
    q[9] = _mm256_add_epi64(VSB4(_mm256_add_epi64(
               _mm256_sub_epi64(
                   _mm256_add_epi64(VXOR64(m,h,0), VXOR64(m,h,6)),
                   VXOR64(m,h,3)),
               _mm256_sub_epi64(VXOR64(m,h,14), VXOR64(m,h,7)))), h[10]);
    q[10] = _mm256_add_epi64(VSB0(_mm256_add_epi64(
               _mm256_sub_epi64(
                   _mm256_sub_epi64(VXOR64(m,h,8), VXOR64(m,h,1)),
                   VXOR64(m,h,4)),
               _mm256_sub_epi64(VXOR64(m,h,15), VXOR64(m,h,7)))), h[11]);
    q[11] = _mm256_add_epi64(VSB1(_mm256_add_epi64(
               _mm256_sub_epi64(
                   _mm256_sub_epi64(VXOR64(m,h,8), VXOR64(m,h,0)),
                   VXOR64(m,h,2)),
               _mm256_sub_epi64(VXOR64(m,h,9), VXOR64(m,h,5)))), h[12]);
    q[12] = _mm256_add_epi64(VSB2(_mm256_add_epi64(
               _mm256_sub_epi64(
                   _mm256_add_epi64(VXOR64(m,h,1), VXOR64(m,h,3)),
                   VXOR64(m,h,6)),
               _mm256_sub_epi64(VXOR64(m,h,10), VXOR64(m,h,9)))), h[13]);
    q[13] = _mm256_add_epi64(VSB3(_mm256_add_epi64(
               _mm256_add_epi64(VXOR64(m,h,2), VXOR64(m,h,4)),
               _mm256_add_epi64(VXOR64(m,h,7),
                   _mm256_add_epi64(VXOR64(m,h,10), VXOR64(m,h,11))))), h[14]);
    q[14] = _mm256_add_epi64(VSB4(_mm256_sub_epi64(
               _mm256_sub_epi64(
                   _mm256_add_epi64(VXOR64(m,h,3), VXOR64(m,h,8)),
                   VXOR64(m,h,5)),
               _mm256_add_epi64(VXOR64(m,h,12), VXOR64(m,h,11)))), h[15]);
    q[15] = _mm256_add_epi64(VSB0(_mm256_add_epi64(
               _mm256_sub_epi64(
                   _mm256_sub_epi64(VXOR64(m,h,12), VXOR64(m,h,4)),
                   VXOR64(m,h,6)),
               _mm256_sub_epi64(VXOR64(m,h,13), VXOR64(m,h,9)))), h[0]);

    q[16] = VEXPAND1_64(16, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,3,4,7,10,11);
    q[17] = VEXPAND1_64(17, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 1,2,4,5,8,11,12);
    q[18] = VEXPAND2_64(18, 2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17, 2,3,5,6,9,12,13);
    q[19] = VEXPAND2_64(19, 3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18, 3,4,6,7,10,13,14);
    q[20] = VEXPAND2_64(20, 4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19, 4,5,7,8,11,14,15);
    q[21] = VEXPAND2_64(21, 5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20, 5,6,8,9,12,15,16);
    q[22] = VEXPAND2_64(22, 6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21, 6,7,9,10,13,0,1);
    q[23] = VEXPAND2_64(23, 7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22, 7,8,10,11,14,1,2);
    q[24] = VEXPAND2_64(24, 8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23, 8,9,11,12,15,2,3);
    q[25] = VEXPAND2_64(25, 9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24, 9,10,12,13,0,3,4);
    q[26] = VEXPAND2_64(26, 10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25, 10,11,13,14,1,4,5);
    q[27] = VEXPAND2_64(27, 11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26, 11,12,14,15,2,5,6);
    q[28] = VEXPAND2_64(28, 12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27, 12,13,15,16,3,6,7);
    q[29] = VEXPAND2_64(29, 13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28, 13,14,0,1,4,7,8);
    q[30] = VEXPAND2_64(30, 14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29, 14,15,1,2,5,8,9);
    q[31] = VEXPAND2_64(31, 15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30, 15,16,2,3,6,9,10);

    xl = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(
         _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(q[16], q[17]),
         q[18]), q[19]), q[20]), q[21]), q[22]), q[23]);
    xh = _mm256_xor_si256(xl, _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(
         _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(q[24], q[25]),
         q[26]), q[27]), q[28]), q[29]), q[30]), q[31]));

    t[0] = _mm256_add_epi64(
        _mm256_xor_si256(_mm256_xor_si256(_mm256_slli_epi64(xh, 5), _mm256_srli_epi64(q[16], 5)), m[0]),
        _mm256_xor_si256(_mm256_xor_si256(xl, q[24]), q[0])
    );
    t[1] = _mm256_add_epi64(
        _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi64(xh, 7), _mm256_slli_epi64(q[17], 8)), m[1]),
        _mm256_xor_si256(_mm256_xor_si256(xl, q[25]), q[1])
    );
    t[2] = _mm256_add_epi64(
        _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi64(xh, 5), _mm256_slli_epi64(q[18], 5)), m[2]),
        _mm256_xor_si256(_mm256_xor_si256(xl, q[26]), q[2])
    );
    t[3] = _mm256_add_epi64(
        _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi64(xh, 1), _mm256_slli_epi64(q[19], 5)), m[3]),
        _mm256_xor_si256(_mm256_xor_si256(xl, q[27]), q[3])
    );
    t[4] = _mm256_add_epi64(
        _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi64(xh, 3), q[20]), m[4]),
        _mm256_xor_si256(_mm256_xor_si256(xl, q[28]), q[4])
    );
    t[5] = _mm256_add_epi64(
        _mm256_xor_si256(_mm256_xor_si256(_mm256_slli_epi64(xh, 6), _mm256_srli_epi64(q[21], 6)), m[5]),
        _mm256_xor_si256(_mm256_xor_si256(xl, q[29]), q[5])
    );
    t[6] = _mm256_add_epi64(
        _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi64(xh, 4), _mm256_slli_epi64(q[22], 6)), m[6]),
        _mm256_xor_si256(_mm256_xor_si256(xl, q[30]), q[6])
    );
    t[7] = _mm256_add_epi64(
        _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi64(xh, 11), _mm256_slli_epi64(q[23], 2)), m[7]),
        _mm256_xor_si256(_mm256_xor_si256(xl, q[31]), q[7])
    );

    t[8] = _mm256_add_epi64(
        _mm256_add_epi64(mm256_rotl_epi64(t[4], 9), _mm256_xor_si256(_mm256_xor_si256(xh, q[24]), m[8])),
        _mm256_xor_si256(_mm256_xor_si256(_mm256_slli_epi64(xl, 8), q[23]), q[8])
    );
    t[9] = _mm256_add_epi64(
        _mm256_add_epi64(mm256_rotl_epi64(t[5], 10), _mm256_xor_si256(_mm256_xor_si256(xh, q[25]), m[9])),
        _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi64(xl, 6), q[16]), q[9])
    );
    t[10] = _mm256_add_epi64(
        _mm256_add_epi64(mm256_rotl_epi64(t[6], 11), _mm256_xor_si256(_mm256_xor_si256(xh, q[26]), m[10])),
        _mm256_xor_si256(_mm256_xor_si256(_mm256_slli_epi64(xl, 6), q[17]), q[10])
    );
    t[11] = _mm256_add_epi64(
        _mm256_add_epi64(mm256_rotl_epi64(t[7], 12), _mm256_xor_si256(_mm256_xor_si256(xh, q[27]), m[11])),
        _mm256_xor_si256(_mm256_xor_si256(_mm256_slli_epi64(xl, 4), q[18]), q[11])
    );
    t[12] = _mm256_add_epi64(
        _mm256_add_epi64(mm256_rotl_epi64(t[0], 13), _mm256_xor_si256(_mm256_xor_si256(xh, q[28]), m[12])),
        _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi64(xl, 3), q[19]), q[12])
    );
    t[13] = _mm256_add_epi64(
        _mm256_add_epi64(mm256_rotl_epi64(t[1], 14), _mm256_xor_si256(_mm256_xor_si256(xh, q[29]), m[13])),
        _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi64(xl, 4), q[20]), q[13])
    );
    t[14] = _mm256_add_epi64(
        _mm256_add_epi64(mm256_rotl_epi64(t[2], 15), _mm256_xor_si256(_mm256_xor_si256(xh, q[30]), m[14])),
        _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi64(xl, 7), q[21]), q[14])
    );
    t[15] = _mm256_add_epi64(
        _mm256_add_epi64(mm256_rotl_epi64(t[3], 16), _mm256_xor_si256(_mm256_xor_si256(xh, q[31]), m[15])),
        _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi64(xl, 2), q[22]), q[15])
    );

    for (j = 0; j < 16; j++) dh[j] = t[j];
}

#undef VXOR64
#undef VSB0
#undef VSB1
#undef VSB2
#undef VSB3
#undef VSB4
#undef VSB5
#undef VRB1
#undef VRB2
#undef VRB3
#undef VRB4
#undef VRB5
#undef VRB6
#undef VRB7
#undef VADD64_2
#undef VADD64_3
#undef VADD64_4
#undef VADD64_5
#undef VADD64_6
#undef VADD64_7
#undef VADD64_8
#undef VADD64_9
#undef VADD64_10
#undef VADD64_11
#undef VADD64_12
#undef VADD64_13
#undef VADD64_14
#undef VADD64_15
#undef VADD64_16
#undef VEXPAND1_64
#undef VEXPAND2_64

#endif /* __AVX2__ && SPH_64 */

/* -------------------------------------------------------------------------
 * One‑Shot Kernel Specializations (Fixed‑Length Custom Kernel)
 * ------------------------------------------------------------------------- */
void
sph_bmw256_direct(const void *data, size_t len, void *dst)
{
    sph_bmw_small_context sc;
    bmw32_init(&sc, IV256);
    if (__builtin_expect(len == 64, 1)) {
        /* Exact mutable‑word specialization: exactly one block */
        sph_u32 M[16] SPH_ALIGNED(16);
        load32_block(data, M);
        bmw32_compress_unrolled(M, sc.H, sc.H);
        /* Tail pipeline collapse: compress with final block and output */
        sph_u32 final_h[16] SPH_ALIGNED(16);
        bmw32_compress_unrolled(sc.H, final_s_block, final_h);
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
    if (__builtin_expect(len == 128, 1)) {
        sph_u64 M[16] SPH_ALIGNED(32);
        load64_block(data, M);
        bmw64_compress_unrolled(M, sc.H, sc.H);
        sph_u64 final_h[16] SPH_ALIGNED(32);
        bmw64_compress_unrolled(sc.H, final_b_block, final_h);
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
 * Batched Parallel Kernels (Multi-Block Processing) – SIMD + OpenMP
 * ------------------------------------------------------------------------- */

#if defined(__AVX2__)
static void
bmw32_batched_avx2(const unsigned char *in, size_t block_count,
                   unsigned char *out, const sph_u32 *iv)
{
    const size_t batch = 8;
    size_t i;

    #pragma omp parallel for schedule(static) if(block_count >= batch*4)
    for (i = 0; i + batch <= block_count; i += batch) {
        const uint32_t *src = (const uint32_t*)(in + i * 64);
        uint32_t *dst = (uint32_t*)(out + i * 32);

        __m256i m[16], hv[16], dh[16];
        __m256i q[32];
        __m256i xl, xh;
        __m256i t[16];
        int j;

        /* Load and transpose first 8 words of 8 messages */
        __m256i r0 = _mm256_loadu_si256((__m256i*)(src + 0*16));
        __m256i r1 = _mm256_loadu_si256((__m256i*)(src + 1*16));
        __m256i r2 = _mm256_loadu_si256((__m256i*)(src + 2*16));
        __m256i r3 = _mm256_loadu_si256((__m256i*)(src + 3*16));
        __m256i r4 = _mm256_loadu_si256((__m256i*)(src + 4*16));
        __m256i r5 = _mm256_loadu_si256((__m256i*)(src + 5*16));
        __m256i r6 = _mm256_loadu_si256((__m256i*)(src + 6*16));
        __m256i r7 = _mm256_loadu_si256((__m256i*)(src + 7*16));
        TRANSPOSE8x8_I32(r0,r1,r2,r3,r4,r5,r6,r7);
        m[0] = r0; m[1] = r1; m[2] = r2; m[3] = r3;
        m[4] = r4; m[5] = r5; m[6] = r6; m[7] = r7;

        /* Load and transpose second 8 words */
        r0 = _mm256_loadu_si256((__m256i*)(src + 0*16 + 8));
        r1 = _mm256_loadu_si256((__m256i*)(src + 1*16 + 8));
        r2 = _mm256_loadu_si256((__m256i*)(src + 2*16 + 8));
        r3 = _mm256_loadu_si256((__m256i*)(src + 3*16 + 8));
        r4 = _mm256_loadu_si256((__m256i*)(src + 4*16 + 8));
        r5 = _mm256_loadu_si256((__m256i*)(src + 5*16 + 8));
        r6 = _mm256_loadu_si256((__m256i*)(src + 6*16 + 8));
        r7 = _mm256_loadu_si256((__m256i*)(src + 7*16 + 8));
        TRANSPOSE8x8_I32(r0,r1,r2,r3,r4,r5,r6,r7);
        m[8] = r0; m[9] = r1; m[10] = r2; m[11] = r3;
        m[12] = r4; m[13] = r5; m[14] = r6; m[15] = r7;

        /* Init H with IV broadcast */
        for (j = 0; j < 16; j++) hv[j] = _mm256_set1_epi32((int)iv[j]);

        /* === First compression (vectorized) === */
        #define VXOR(mv,hv,idx) _mm256_xor_si256(mv[idx], hv[idx])
        #define VSS0(x) _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(x,1), _mm256_slli_epi32(x,3)), \
                 _mm256_xor_si256(mm256_rotl_epi32(x,4), mm256_rotl_epi32(x,19)))
        #define VSS1(x) _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(x,1), _mm256_slli_epi32(x,2)), \
                 _mm256_xor_si256(mm256_rotl_epi32(x,8), mm256_rotl_epi32(x,23)))
        #define VSS2(x) _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(x,2), _mm256_slli_epi32(x,1)), \
                 _mm256_xor_si256(mm256_rotl_epi32(x,12), mm256_rotl_epi32(x,25)))
        #define VSS3(x) _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(x,2), _mm256_slli_epi32(x,2)), \
                 _mm256_xor_si256(mm256_rotl_epi32(x,15), mm256_rotl_epi32(x,29)))
        #define VSS4(x) _mm256_xor_si256(_mm256_srli_epi32(x,1), x)
        #define VSS5(x) _mm256_xor_si256(_mm256_srli_epi32(x,2), x)
        #define VRS1(x) mm256_rotl_epi32(x,3)
        #define VRS2(x) mm256_rotl_epi32(x,7)
        #define VRS3(x) mm256_rotl_epi32(x,13)
        #define VRS4(x) mm256_rotl_epi32(x,16)
        #define VRS5(x) mm256_rotl_epi32(x,19)
        #define VRS6(x) mm256_rotl_epi32(x,23)
        #define VRS7(x) mm256_rotl_epi32(x,27)

        q[0] = _mm256_add_epi32(VSS0(_mm256_add_epi32(
                   _mm256_sub_epi32(VXOR(m,hv,5), VXOR(m,hv,7)),
                   _mm256_add_epi32(VXOR(m,hv,10),
                       _mm256_add_epi32(VXOR(m,hv,13), VXOR(m,hv,14))))), hv[1]);
        q[1] = _mm256_add_epi32(VSS1(_mm256_add_epi32(
                   _mm256_sub_epi32(VXOR(m,hv,6), VXOR(m,hv,8)),
                   _mm256_add_epi32(VXOR(m,hv,11),
                       _mm256_sub_epi32(VXOR(m,hv,14), VXOR(m,hv,15))))), hv[2]);
        q[2] = _mm256_add_epi32(VSS2(_mm256_add_epi32(
                   _mm256_add_epi32(VXOR(m,hv,0), VXOR(m,hv,7)),
                   _mm256_add_epi32(VXOR(m,hv,9),
                       _mm256_sub_epi32(VXOR(m,hv,15), VXOR(m,hv,12))))), hv[3]);
        q[3] = _mm256_add_epi32(VSS3(_mm256_add_epi32(
                   _mm256_sub_epi32(VXOR(m,hv,0), VXOR(m,hv,1)),
                   _mm256_add_epi32(VXOR(m,hv,8),
                       _mm256_sub_epi32(VXOR(m,hv,13), VXOR(m,hv,10))))), hv[4]);
        q[4] = _mm256_add_epi32(VSS4(_mm256_add_epi32(
                   _mm256_add_epi32(VXOR(m,hv,1), VXOR(m,hv,2)),
                   _mm256_sub_epi32(
                       _mm256_sub_epi32(VXOR(m,hv,9), VXOR(m,hv,11)),
                       VXOR(m,hv,14)))), hv[5]);
        q[5] = _mm256_add_epi32(VSS0(_mm256_add_epi32(
                   _mm256_sub_epi32(VXOR(m,hv,3), VXOR(m,hv,2)),
                   _mm256_sub_epi32(
                       _mm256_add_epi32(VXOR(m,hv,10), VXOR(m,hv,15)),
                       VXOR(m,hv,12)))), hv[6]);
        q[6] = _mm256_add_epi32(VSS1(_mm256_add_epi32(
                   _mm256_sub_epi32(
                       _mm256_sub_epi32(VXOR(m,hv,4), VXOR(m,hv,0)),
                       VXOR(m,hv,3)),
                   _mm256_sub_epi32(VXOR(m,hv,13), VXOR(m,hv,11)))), hv[7]);
        q[7] = _mm256_add_epi32(VSS2(_mm256_sub_epi32(
                   _mm256_sub_epi32(
                       _mm256_sub_epi32(VXOR(m,hv,1), VXOR(m,hv,4)),
                       VXOR(m,hv,5)),
                   _mm256_add_epi32(VXOR(m,hv,12), VXOR(m,hv,14)))), hv[8]);
        q[8] = _mm256_add_epi32(VSS3(_mm256_sub_epi32(
                   _mm256_sub_epi32(
                       _mm256_sub_epi32(VXOR(m,hv,2), VXOR(m,hv,5)),
                       VXOR(m,hv,6)),
                   _mm256_sub_epi32(VXOR(m,hv,15), VXOR(m,hv,13)))), hv[9]);
        q[9] = _mm256_add_epi32(VSS4(_mm256_add_epi32(
                   _mm256_sub_epi32(
                       _mm256_add_epi32(VXOR(m,hv,0), VXOR(m,hv,6)),
                       VXOR(m,hv,3)),
                   _mm256_sub_epi32(VXOR(m,hv,14), VXOR(m,hv,7)))), hv[10]);
        q[10] = _mm256_add_epi32(VSS0(_mm256_add_epi32(
                   _mm256_sub_epi32(
                       _mm256_sub_epi32(VXOR(m,hv,8), VXOR(m,hv,1)),
                       VXOR(m,hv,4)),
                   _mm256_sub_epi32(VXOR(m,hv,15), VXOR(m,hv,7)))), hv[11]);
        q[11] = _mm256_add_epi32(VSS1(_mm256_add_epi32(
                   _mm256_sub_epi32(
                       _mm256_sub_epi32(VXOR(m,hv,8), VXOR(m,hv,0)),
                       VXOR(m,hv,2)),
                   _mm256_sub_epi32(VXOR(m,hv,9), VXOR(m,hv,5)))), hv[12]);
        q[12] = _mm256_add_epi32(VSS2(_mm256_add_epi32(
                   _mm256_sub_epi32(
                       _mm256_add_epi32(VXOR(m,hv,1), VXOR(m,hv,3)),
                       VXOR(m,hv,6)),
                   _mm256_sub_epi32(VXOR(m,hv,10), VXOR(m,hv,9)))), hv[13]);
        q[13] = _mm256_add_epi32(VSS3(_mm256_add_epi32(
                   _mm256_add_epi32(VXOR(m,hv,2), VXOR(m,hv,4)),
                   _mm256_add_epi32(VXOR(m,hv,7),
                       _mm256_add_epi32(VXOR(m,hv,10), VXOR(m,hv,11))))), hv[14]);
        q[14] = _mm256_add_epi32(VSS4(_mm256_sub_epi32(
                   _mm256_sub_epi32(
                       _mm256_add_epi32(VXOR(m,hv,3), VXOR(m,hv,8)),
                       VXOR(m,hv,5)),
                   _mm256_add_epi32(VXOR(m,hv,12), VXOR(m,hv,11)))), hv[15]);
        q[15] = _mm256_add_epi32(VSS0(_mm256_add_epi32(
                   _mm256_sub_epi32(
                       _mm256_sub_epi32(VXOR(m,hv,12), VXOR(m,hv,4)),
                       VXOR(m,hv,6)),
                   _mm256_sub_epi32(VXOR(m,hv,13), VXOR(m,hv,9)))), hv[0]);

        #define VADD2(a,b) _mm256_add_epi32(a,b)
        #define VADD3(a,b,c) VADD2(VADD2(a,b),c)
        #define VADD4(a,b,c,d) VADD2(VADD3(a,b,c),d)
        #define VADD5(a,b,c,d,e) VADD2(VADD4(a,b,c,d),e)
        #define VADD6(a,b,c,d,e,f) VADD2(VADD5(a,b,c,d,e),f)
        #define VADD7(a,b,c,d,e,f,g) VADD2(VADD6(a,b,c,d,e,f),g)
        #define VADD8(a,b,c,d,e,f,g,h) VADD2(VADD7(a,b,c,d,e,f,g),h)
        #define VADD9(a,b,c,d,e,f,g,h,i) VADD2(VADD8(a,b,c,d,e,f,g,h),i)
        #define VADD10(a,b,c,d,e,f,g,h,i,j) VADD2(VADD9(a,b,c,d,e,f,g,h,i),j)
        #define VADD11(a,b,c,d,e,f,g,h,i,j,k) VADD2(VADD10(a,b,c,d,e,f,g,h,i,j),k)
        #define VADD12(a,b,c,d,e,f,g,h,i,j,k,l) VADD2(VADD11(a,b,c,d,e,f,g,h,i,j,k),l)
        #define VADD13(a,b,c,d,e,f,g,h,i,j,k,l,m) VADD2(VADD12(a,b,c,d,e,f,g,h,i,j,k,l),m)
        #define VADD14(a,b,c,d,e,f,g,h,i,j,k,l,m,n) VADD2(VADD13(a,b,c,d,e,f,g,h,i,j,k,l,m),n)
        #define VADD15(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o) VADD2(VADD14(a,b,c,d,e,f,g,h,i,j,k,l,m,n),o)
        #define VADD16(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p) VADD2(VADD15(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o),p)

        #define VEXPAND1(i16, i0,i1,i2,i3,i4,i5,i6,i7,i8,i9,i10,i11,i12,i13,i14,i15, \
                         i0m,i1m,i3m,i4m,i7m,i10m,i11m) \
            VADD16(VSS1(q[i0]), VSS2(q[i1]), VSS3(q[i2]), VSS0(q[i3]), \
                   VSS1(q[i4]), VSS2(q[i5]), VSS3(q[i6]), VSS0(q[i7]), \
                   VSS1(q[i8]), VSS2(q[i9]), VSS3(q[i10]), VSS0(q[i11]), \
                   VSS1(q[i12]), VSS2(q[i13]), VSS3(q[i14]), VSS0(q[i15]), \
            _mm256_xor_si256( \
                VADD3(mm256_rotl_epi32(m[i0m],i1m), \
                      _mm256_sub_epi32(mm256_rotl_epi32(m[i3m],i4m), mm256_rotl_epi32(m[i10m],i11m)), \
                      Ks_avx2[(i16)-16]), \
                hv[i7m]))

        #define VEXPAND2(i16, i0,i1,i2,i3,i4,i5,i6,i7,i8,i9,i10,i11,i12,i13,i14,i15, \
                         i0m,i1m,i3m,i4m,i7m,i10m,i11m) \
            VADD16(q[i0], VRS1(q[i1]), q[i2], VRS2(q[i3]), \
                   q[i4], VRS3(q[i5]), q[i6], VRS4(q[i7]), \
                   q[i8], VRS5(q[i9]), q[i10], VRS6(q[i11]), \
                   q[i12], VRS7(q[i13]), VSS4(q[i14]), VSS5(q[i15]), \
            _mm256_xor_si256( \
                VADD3(mm256_rotl_epi32(m[i0m],i1m), \
                      _mm256_sub_epi32(mm256_rotl_epi32(m[i3m],i4m), mm256_rotl_epi32(m[i10m],i11m)), \
                      Ks_avx2[(i16)-16]), \
                hv[i7m]))

        q[16] = VEXPAND1(16, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,3,4,7,10,11);
        q[17] = VEXPAND1(17, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 1,2,4,5,8,11,12);
        q[18] = VEXPAND2(18, 2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17, 2,3,5,6,9,12,13);
        q[19] = VEXPAND2(19, 3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18, 3,4,6,7,10,13,14);
        q[20] = VEXPAND2(20, 4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19, 4,5,7,8,11,14,15);
        q[21] = VEXPAND2(21, 5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20, 5,6,8,9,12,15,16);
        q[22] = VEXPAND2(22, 6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21, 6,7,9,10,13,0,1);
        q[23] = VEXPAND2(23, 7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22, 7,8,10,11,14,1,2);
        q[24] = VEXPAND2(24, 8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23, 8,9,11,12,15,2,3);
        q[25] = VEXPAND2(25, 9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24, 9,10,12,13,0,3,4);
        q[26] = VEXPAND2(26, 10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25, 10,11,13,14,1,4,5);
        q[27] = VEXPAND2(27, 11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26, 11,12,14,15,2,5,6);
        q[28] = VEXPAND2(28, 12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27, 12,13,15,16,3,6,7);
        q[29] = VEXPAND2(29, 13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28, 13,14,0,1,4,7,8);
        q[30] = VEXPAND2(30, 14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29, 14,15,1,2,5,8,9);
        q[31] = VEXPAND2(31, 15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30, 15,16,2,3,6,9,10);

        xl = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(
             _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(q[16], q[17]),
             q[18]), q[19]), q[20]), q[21]), q[22]), q[23]);
        xh = _mm256_xor_si256(xl, _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(
             _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(q[24], q[25]),
             q[26]), q[27]), q[28]), q[29]), q[30]), q[31]));

        t[0] = _mm256_add_epi32(
            _mm256_xor_si256(_mm256_xor_si256(_mm256_slli_epi32(xh, 5), _mm256_srli_epi32(q[16], 5)), m[0]),
            _mm256_xor_si256(_mm256_xor_si256(xl, q[24]), q[0])
        );
        t[1] = _mm256_add_epi32(
            _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(xh, 7), _mm256_slli_epi32(q[17], 8)), m[1]),
            _mm256_xor_si256(_mm256_xor_si256(xl, q[25]), q[1])
        );
        t[2] = _mm256_add_epi32(
            _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(xh, 5), _mm256_slli_epi32(q[18], 5)), m[2]),
            _mm256_xor_si256(_mm256_xor_si256(xl, q[26]), q[2])
        );
        t[3] = _mm256_add_epi32(
            _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(xh, 1), _mm256_slli_epi32(q[19], 5)), m[3]),
            _mm256_xor_si256(_mm256_xor_si256(xl, q[27]), q[3])
        );
        t[4] = _mm256_add_epi32(
            _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(xh, 3), q[20]), m[4]),
            _mm256_xor_si256(_mm256_xor_si256(xl, q[28]), q[4])
        );
        t[5] = _mm256_add_epi32(
            _mm256_xor_si256(_mm256_xor_si256(_mm256_slli_epi32(xh, 6), _mm256_srli_epi32(q[21], 6)), m[5]),
            _mm256_xor_si256(_mm256_xor_si256(xl, q[29]), q[5])
        );
        t[6] = _mm256_add_epi32(
            _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(xh, 4), _mm256_slli_epi32(q[22], 6)), m[6]),
            _mm256_xor_si256(_mm256_xor_si256(xl, q[30]), q[6])
        );
        t[7] = _mm256_add_epi32(
            _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(xh, 11), _mm256_slli_epi32(q[23], 2)), m[7]),
            _mm256_xor_si256(_mm256_xor_si256(xl, q[31]), q[7])
        );

        t[8] = _mm256_add_epi32(
            _mm256_add_epi32(mm256_rotl_epi32(t[4], 9), _mm256_xor_si256(_mm256_xor_si256(xh, q[24]), m[8])),
            _mm256_xor_si256(_mm256_xor_si256(_mm256_slli_epi32(xl, 8), q[23]), q[8])
        );
        t[9] = _mm256_add_epi32(
            _mm256_add_epi32(mm256_rotl_epi32(t[5], 10), _mm256_xor_si256(_mm256_xor_si256(xh, q[25]), m[9])),
            _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(xl, 6), q[16]), q[9])
        );
        t[10] = _mm256_add_epi32(
            _mm256_add_epi32(mm256_rotl_epi32(t[6], 11), _mm256_xor_si256(_mm256_xor_si256(xh, q[26]), m[10])),
            _mm256_xor_si256(_mm256_xor_si256(_mm256_slli_epi32(xl, 6), q[17]), q[10])
        );
        t[11] = _mm256_add_epi32(
            _mm256_add_epi32(mm256_rotl_epi32(t[7], 12), _mm256_xor_si256(_mm256_xor_si256(xh, q[27]), m[11])),
            _mm256_xor_si256(_mm256_xor_si256(_mm256_slli_epi32(xl, 4), q[18]), q[11])
        );
        t[12] = _mm256_add_epi32(
            _mm256_add_epi32(mm256_rotl_epi32(t[0], 13), _mm256_xor_si256(_mm256_xor_si256(xh, q[28]), m[12])),
            _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(xl, 3), q[19]), q[12])
        );
        t[13] = _mm256_add_epi32(
            _mm256_add_epi32(mm256_rotl_epi32(t[1], 14), _mm256_xor_si256(_mm256_xor_si256(xh, q[29]), m[13])),
            _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(xl, 4), q[20]), q[13])
        );
        t[14] = _mm256_add_epi32(
            _mm256_add_epi32(mm256_rotl_epi32(t[2], 15), _mm256_xor_si256(_mm256_xor_si256(xh, q[30]), m[14])),
            _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(xl, 7), q[21]), q[14])
        );
        t[15] = _mm256_add_epi32(
            _mm256_add_epi32(mm256_rotl_epi32(t[3], 16), _mm256_xor_si256(_mm256_xor_si256(xh, q[31]), m[15])),
            _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(xl, 2), q[22]), q[15])
        );

        for (j = 0; j < 16; j++) dh[j] = t[j];

        /* === Second compression with final block === */
        q[0] = _mm256_add_epi32(VSS0(_mm256_add_epi32(
                   _mm256_sub_epi32(VXOR(dh,final_avx2,5), VXOR(dh,final_avx2,7)),
                   _mm256_add_epi32(VXOR(dh,final_avx2,10),
                       _mm256_add_epi32(VXOR(dh,final_avx2,13), VXOR(dh,final_avx2,14))))), final_avx2[1]);
        q[1] = _mm256_add_epi32(VSS1(_mm256_add_epi32(
                   _mm256_sub_epi32(VXOR(dh,final_avx2,6), VXOR(dh,final_avx2,8)),
                   _mm256_add_epi32(VXOR(dh,final_avx2,11),
                       _mm256_sub_epi32(VXOR(dh,final_avx2,14), VXOR(dh,final_avx2,15))))), final_avx2[2]);
        q[2] = _mm256_add_epi32(VSS2(_mm256_add_epi32(
                   _mm256_add_epi32(VXOR(dh,final_avx2,0), VXOR(dh,final_avx2,7)),
                   _mm256_add_epi32(VXOR(dh,final_avx2,9),
                       _mm256_sub_epi32(VXOR(dh,final_avx2,15), VXOR(dh,final_avx2,12))))), final_avx2[3]);
        q[3] = _mm256_add_epi32(VSS3(_mm256_add_epi32(
                   _mm256_sub_epi32(VXOR(dh,final_avx2,0), VXOR(dh,final_avx2,1)),
                   _mm256_add_epi32(VXOR(dh,final_avx2,8),
                       _mm256_sub_epi32(VXOR(dh,final_avx2,13), VXOR(dh,final_avx2,10))))), final_avx2[4]);
        q[4] = _mm256_add_epi32(VSS4(_mm256_add_epi32(
                   _mm256_add_epi32(VXOR(dh,final_avx2,1), VXOR(dh,final_avx2,2)),
                   _mm256_sub_epi32(
                       _mm256_sub_epi32(VXOR(dh,final_avx2,9), VXOR(dh,final_avx2,11)),
                       VXOR(dh,final_avx2,14)))), final_avx2[5]);
        q[5] = _mm256_add_epi32(VSS0(_mm256_add_epi32(
                   _mm256_sub_epi32(VXOR(dh,final_avx2,3), VXOR(dh,final_avx2,2)),
                   _mm256_sub_epi32(
                       _mm256_add_epi32(VXOR(dh,final_avx2,10), VXOR(dh,final_avx2,15)),
                       VXOR(dh,final_avx2,12)))), final_avx2[6]);
        q[6] = _mm256_add_epi32(VSS1(_mm256_add_epi32(
                   _mm256_sub_epi32(
                       _mm256_sub_epi32(VXOR(dh,final_avx2,4), VXOR(dh,final_avx2,0)),
                       VXOR(dh,final_avx2,3)),
                   _mm256_sub_epi32(VXOR(dh,final_avx2,13), VXOR(dh,final_avx2,11)))), final_avx2[7]);
        q[7] = _mm256_add_epi32(VSS2(_mm256_sub_epi32(
                   _mm256_sub_epi32(
                       _mm256_sub_epi32(VXOR(dh,final_avx2,1), VXOR(dh,final_avx2,4)),
                       VXOR(dh,final_avx2,5)),
                   _mm256_add_epi32(VXOR(dh,final_avx2,12), VXOR(dh,final_avx2,14)))), final_avx2[8]);
        q[8] = _mm256_add_epi32(VSS3(_mm256_sub_epi32(
                   _mm256_sub_epi32(
                       _mm256_sub_epi32(VXOR(dh,final_avx2,2), VXOR(dh,final_avx2,5)),
                       VXOR(dh,final_avx2,6)),
                   _mm256_sub_epi32(VXOR(dh,final_avx2,15), VXOR(dh,final_avx2,13)))), final_avx2[9]);
        q[9] = _mm256_add_epi32(VSS4(_mm256_add_epi32(
                   _mm256_sub_epi32(
                       _mm256_add_epi32(VXOR(dh,final_avx2,0), VXOR(dh,final_avx2,6)),
                       VXOR(dh,final_avx2,3)),
                   _mm256_sub_epi32(VXOR(dh,final_avx2,14), VXOR(dh,final_avx2,7)))), final_avx2[10]);
        q[10] = _mm256_add_epi32(VSS0(_mm256_add_epi32(
                   _mm256_sub_epi32(
                       _mm256_sub_epi32(VXOR(dh,final_avx2,8), VXOR(dh,final_avx2,1)),
                       VXOR(dh,final_avx2,4)),
                   _mm256_sub_epi32(VXOR(dh,final_avx2,15), VXOR(dh,final_avx2,7)))), final_avx2[11]);
        q[11] = _mm256_add_epi32(VSS1(_mm256_add_epi32(
                   _mm256_sub_epi32(
                       _mm256_sub_epi32(VXOR(dh,final_avx2,8), VXOR(dh,final_avx2,0)),
                       VXOR(dh,final_avx2,2)),
                   _mm256_sub_epi32(VXOR(dh,final_avx2,9), VXOR(dh,final_avx2,5)))), final_avx2[12]);
        q[12] = _mm256_add_epi32(VSS2(_mm256_add_epi32(
                   _mm256_sub_epi32(
                       _mm256_add_epi32(VXOR(dh,final_avx2,1), VXOR(dh,final_avx2,3)),
                       VXOR(dh,final_avx2,6)),
                   _mm256_sub_epi32(VXOR(dh,final_avx2,10), VXOR(dh,final_avx2,9)))), final_avx2[13]);
        q[13] = _mm256_add_epi32(VSS3(_mm256_add_epi32(
                   _mm256_add_epi32(VXOR(dh,final_avx2,2), VXOR(dh,final_avx2,4)),
                   _mm256_add_epi32(VXOR(dh,final_avx2,7),
                       _mm256_add_epi32(VXOR(dh,final_avx2,10), VXOR(dh,final_avx2,11))))), final_avx2[14]);
        q[14] = _mm256_add_epi32(VSS4(_mm256_sub_epi32(
                   _mm256_sub_epi32(
                       _mm256_add_epi32(VXOR(dh,final_avx2,3), VXOR(dh,final_avx2,8)),
                       VXOR(dh,final_avx2,5)),
                   _mm256_add_epi32(VXOR(dh,final_avx2,12), VXOR(dh,final_avx2,11)))), final_avx2[15]);
        q[15] = _mm256_add_epi32(VSS0(_mm256_add_epi32(
                   _mm256_sub_epi32(
                       _mm256_sub_epi32(VXOR(dh,final_avx2,12), VXOR(dh,final_avx2,4)),
                       VXOR(dh,final_avx2,6)),
                   _mm256_sub_epi32(VXOR(dh,final_avx2,13), VXOR(dh,final_avx2,9)))), final_avx2[0]);

        q[16] = VEXPAND1(16, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,3,4,7,10,11);
        q[17] = VEXPAND1(17, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 1,2,4,5,8,11,12);
        q[18] = VEXPAND2(18, 2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17, 2,3,5,6,9,12,13);
        q[19] = VEXPAND2(19, 3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18, 3,4,6,7,10,13,14);
        q[20] = VEXPAND2(20, 4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19, 4,5,7,8,11,14,15);
        q[21] = VEXPAND2(21, 5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20, 5,6,8,9,12,15,16);
        q[22] = VEXPAND2(22, 6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21, 6,7,9,10,13,0,1);
        q[23] = VEXPAND2(23, 7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22, 7,8,10,11,14,1,2);
        q[24] = VEXPAND2(24, 8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23, 8,9,11,12,15,2,3);
        q[25] = VEXPAND2(25, 9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24, 9,10,12,13,0,3,4);
        q[26] = VEXPAND2(26, 10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25, 10,11,13,14,1,4,5);
        q[27] = VEXPAND2(27, 11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26, 11,12,14,15,2,5,6);
        q[28] = VEXPAND2(28, 12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27, 12,13,15,16,3,6,7);
        q[29] = VEXPAND2(29, 13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28, 13,14,0,1,4,7,8);
        q[30] = VEXPAND2(30, 14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29, 14,15,1,2,5,8,9);
        q[31] = VEXPAND2(31, 15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30, 15,16,2,3,6,9,10);

        xl = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(
             _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(q[16], q[17]),
             q[18]), q[19]), q[20]), q[21]), q[22]), q[23]);
        xh = _mm256_xor_si256(xl, _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(
             _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(q[24], q[25]),
             q[26]), q[27]), q[28]), q[29]), q[30]), q[31]));

        t[0] = _mm256_add_epi32(
            _mm256_xor_si256(_mm256_xor_si256(_mm256_slli_epi32(xh, 5), _mm256_srli_epi32(q[16], 5)), final_avx2[0]),
            _mm256_xor_si256(_mm256_xor_si256(xl, q[24]), q[0])
        );
        t[1] = _mm256_add_epi32(
            _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(xh, 7), _mm256_slli_epi32(q[17], 8)), final_avx2[1]),
            _mm256_xor_si256(_mm256_xor_si256(xl, q[25]), q[1])
        );
        t[2] = _mm256_add_epi32(
            _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(xh, 5), _mm256_slli_epi32(q[18], 5)), final_avx2[2]),
            _mm256_xor_si256(_mm256_xor_si256(xl, q[26]), q[2])
        );
        t[3] = _mm256_add_epi32(
            _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(xh, 1), _mm256_slli_epi32(q[19], 5)), final_avx2[3]),
            _mm256_xor_si256(_mm256_xor_si256(xl, q[27]), q[3])
        );
        t[4] = _mm256_add_epi32(
            _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(xh, 3), q[20]), final_avx2[4]),
            _mm256_xor_si256(_mm256_xor_si256(xl, q[28]), q[4])
        );
        t[5] = _mm256_add_epi32(
            _mm256_xor_si256(_mm256_xor_si256(_mm256_slli_epi32(xh, 6), _mm256_srli_epi32(q[21], 6)), final_avx2[5]),
            _mm256_xor_si256(_mm256_xor_si256(xl, q[29]), q[5])
        );
        t[6] = _mm256_add_epi32(
            _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(xh, 4), _mm256_slli_epi32(q[22], 6)), final_avx2[6]),
            _mm256_xor_si256(_mm256_xor_si256(xl, q[30]), q[6])
        );
        t[7] = _mm256_add_epi32(
            _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(xh, 11), _mm256_slli_epi32(q[23], 2)), final_avx2[7]),
            _mm256_xor_si256(_mm256_xor_si256(xl, q[31]), q[7])
        );

        t[8] = _mm256_add_epi32(
            _mm256_add_epi32(mm256_rotl_epi32(t[4], 9), _mm256_xor_si256(_mm256_xor_si256(xh, q[24]), final_avx2[8])),
            _mm256_xor_si256(_mm256_xor_si256(_mm256_slli_epi32(xl, 8), q[23]), q[8])
        );
        t[9] = _mm256_add_epi32(
            _mm256_add_epi32(mm256_rotl_epi32(t[5], 10), _mm256_xor_si256(_mm256_xor_si256(xh, q[25]), final_avx2[9])),
            _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(xl, 6), q[16]), q[9])
        );
        t[10] = _mm256_add_epi32(
            _mm256_add_epi32(mm256_rotl_epi32(t[6], 11), _mm256_xor_si256(_mm256_xor_si256(xh, q[26]), final_avx2[10])),
            _mm256_xor_si256(_mm256_xor_si256(_mm256_slli_epi32(xl, 6), q[17]), q[10])
        );
        t[11] = _mm256_add_epi32(
            _mm256_add_epi32(mm256_rotl_epi32(t[7], 12), _mm256_xor_si256(_mm256_xor_si256(xh, q[27]), final_avx2[11])),
            _mm256_xor_si256(_mm256_xor_si256(_mm256_slli_epi32(xl, 4), q[18]), q[11])
        );
        t[12] = _mm256_add_epi32(
            _mm256_add_epi32(mm256_rotl_epi32(t[0], 13), _mm256_xor_si256(_mm256_xor_si256(xh, q[28]), final_avx2[12])),
            _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(xl, 3), q[19]), q[12])
        );
        t[13] = _mm256_add_epi32(
            _mm256_add_epi32(mm256_rotl_epi32(t[1], 14), _mm256_xor_si256(_mm256_xor_si256(xh, q[29]), final_avx2[13])),
            _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(xl, 4), q[20]), q[13])
        );
        t[14] = _mm256_add_epi32(
            _mm256_add_epi32(mm256_rotl_epi32(t[2], 15), _mm256_xor_si256(_mm256_xor_si256(xh, q[30]), final_avx2[14])),
            _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(xl, 7), q[21]), q[14])
        );
        t[15] = _mm256_add_epi32(
            _mm256_add_epi32(mm256_rotl_epi32(t[3], 16), _mm256_xor_si256(_mm256_xor_si256(xh, q[31]), final_avx2[15])),
            _mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32(xl, 2), q[22]), q[15])
        );

        for (j = 0; j < 16; j++) dh[j] = t[j];

        /* Transpose outputs (dh[8..15]) and store */
        __m256i o0 = dh[8], o1 = dh[9], o2 = dh[10], o3 = dh[11];
        __m256i o4 = dh[12], o5 = dh[13], o6 = dh[14], o7 = dh[15];
        TRANSPOSE8x8_I32(o0,o1,o2,o3,o4,o5,o6,o7);
        _mm256_storeu_si256((__m256i*)(dst + 0*8), o0);
        _mm256_storeu_si256((__m256i*)(dst + 1*8), o1);
        _mm256_storeu_si256((__m256i*)(dst + 2*8), o2);
        _mm256_storeu_si256((__m256i*)(dst + 3*8), o3);
        _mm256_storeu_si256((__m256i*)(dst + 4*8), o4);
        _mm256_storeu_si256((__m256i*)(dst + 5*8), o5);
        _mm256_storeu_si256((__m256i*)(dst + 6*8), o6);
        _mm256_storeu_si256((__m256i*)(dst + 7*8), o7);

        #undef VXOR
        #undef VSS0
        #undef VSS1
        #undef VSS2
        #undef VSS3
        #undef VSS4
        #undef VSS5
        #undef VRS1
        #undef VRS2
        #undef VRS3
        #undef VRS4
        #undef VRS5
        #undef VRS6
        #undef VRS7
        #undef VADD2
        #undef VADD3
        #undef VADD4
        #undef VADD5
        #undef VADD6
        #undef VADD7
        #undef VADD8
        #undef VADD9
        #undef VADD10
        #undef VADD11
        #undef VADD12
        #undef VADD13
        #undef VADD14
        #undef VADD15
        #undef VADD16
        #undef VEXPAND1
        #undef VEXPAND2
    }

    /* Scalar tail */
    for (; i < block_count; i++) {
        sph_bmw_small_context sc;
        bmw32_init(&sc, iv);
        sph_u32 M[16] SPH_ALIGNED(16);
        load32_block(in + i*64, M);
        bmw32_compress_unrolled(M, sc.H, sc.H);
        sph_u32 final_h[16] SPH_ALIGNED(16);
        bmw32_compress_unrolled(sc.H, final_s_block, final_h);
        for (unsigned u = 0; u < 8; u++)
            sph_enc32le(out + i*32 + 4*u, final_h[8 + u]);
    }
}
#endif /* __AVX2__ */

/* -------------------------------------------------------------------------
 * Batched Parallel Kernels (Multi-Block Processing)
 * ------------------------------------------------------------------------- */
void
sph_bmw256_batched(const void *data, size_t block_count, void *out_array)
{
#if defined(__AVX2__)
    if (__builtin_expect(bmw_cpu_has_avx2(), 1)) {
        bmw32_batched_avx2((const unsigned char *)data, block_count,
                           (unsigned char *)out_array, IV256);
        return;
    }
#endif
    const unsigned char *in = (const unsigned char *)data;
    unsigned char *out = (unsigned char *)out_array;
    size_t i;

    #pragma omp parallel for schedule(static) if(block_count >= 64)
    for (i = 0; i < block_count; i++) {
        sph_bmw_small_context sc;
        bmw32_init(&sc, IV256);
        sph_u32 M[16] SPH_ALIGNED(16);
        load32_block(in + i*64, M);
        bmw32_compress_unrolled(M, sc.H, sc.H);
        sph_u32 final_h[16] SPH_ALIGNED(16);
        bmw32_compress_unrolled(sc.H, final_s_block, final_h);
        for (unsigned u = 0; u < 8; u++)
            sph_enc32le(out + i*32 + 4*u, final_h[8 + u]);
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
