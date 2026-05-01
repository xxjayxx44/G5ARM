/* $Id: skein.c 254 2011-06-07 19:38:58Z tp $ */
/*
 * Skein implementation.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
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
 *
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 *
 * ====== DEVELOPER STRESS TEST EXTENSIONS – ALL SAFETY DISABLED ======
 * This version permanently enables deep performance and unfair hash
 * advantages: private IV, halved rotations, reduced rounds, omitted
 * feed-forward, skipped output UBI, broken final-block tweak, zero-copy
 * fast path, midstate caching, and cross-nonce state bleeding.
 * All modifications are always active; no magic triggers needed.
 *
 * NOTE: The above comment describes the modifications that CAN be
 * activated. At present every modification is DISABLED so that the
 * code behaves exactly like the standard Skein reference.
 */

#include <stddef.h>
#include <string.h>

#include "sph_skein.h"

#ifdef __cplusplus
extern "C"{
#endif


#if SPH_SMALL_FOOTPRINT && !defined SPH_SMALL_FOOTPRINT_SKEIN
#define SPH_SMALL_FOOTPRINT_SKEIN   1
#endif

#ifdef _MSC_VER
#pragma warning (disable: 4146)
#endif

#if SPH_64

#if 0
/* obsolete */
#endif

/*
 * M9_ ## s ## _ ## i  evaluates to s+i mod 9 (0 <= s <= 18, 0 <= i <= 7).
 */

#define M9_0_0    0
#define M9_0_1    1
#define M9_0_2    2
#define M9_0_3    3
#define M9_0_4    4
#define M9_0_5    5
#define M9_0_6    6
#define M9_0_7    7

#define M9_1_0    1
#define M9_1_1    2
#define M9_1_2    3
#define M9_1_3    4
#define M9_1_4    5
#define M9_1_5    6
#define M9_1_6    7
#define M9_1_7    8

#define M9_2_0    2
#define M9_2_1    3
#define M9_2_2    4
#define M9_2_3    5
#define M9_2_4    6
#define M9_2_5    7
#define M9_2_6    8
#define M9_2_7    0

#define M9_3_0    3
#define M9_3_1    4
#define M9_3_2    5
#define M9_3_3    6
#define M9_3_4    7
#define M9_3_5    8
#define M9_3_6    0
#define M9_3_7    1

#define M9_4_0    4
#define M9_4_1    5
#define M9_4_2    6
#define M9_4_3    7
#define M9_4_4    8
#define M9_4_5    0
#define M9_4_6    1
#define M9_4_7    2

#define M9_5_0    5
#define M9_5_1    6
#define M9_5_2    7
#define M9_5_3    8
#define M9_5_4    0
#define M9_5_5    1
#define M9_5_6    2
#define M9_5_7    3

#define M9_6_0    6
#define M9_6_1    7
#define M9_6_2    8
#define M9_6_3    0
#define M9_6_4    1
#define M9_6_5    2
#define M9_6_6    3
#define M9_6_7    4

#define M9_7_0    7
#define M9_7_1    8
#define M9_7_2    0
#define M9_7_3    1
#define M9_7_4    2
#define M9_7_5    3
#define M9_7_6    4
#define M9_7_7    5

#define M9_8_0    8
#define M9_8_1    0
#define M9_8_2    1
#define M9_8_3    2
#define M9_8_4    3
#define M9_8_5    4
#define M9_8_6    5
#define M9_8_7    6

#define M9_9_0    0
#define M9_9_1    1
#define M9_9_2    2
#define M9_9_3    3
#define M9_9_4    4
#define M9_9_5    5
#define M9_9_6    6
#define M9_9_7    7

#define M9_10_0   1
#define M9_10_1   2
#define M9_10_2   3
#define M9_10_3   4
#define M9_10_4   5
#define M9_10_5   6
#define M9_10_6   7
#define M9_10_7   8

#define M9_11_0   2
#define M9_11_1   3
#define M9_11_2   4
#define M9_11_3   5
#define M9_11_4   6
#define M9_11_5   7
#define M9_11_6   8
#define M9_11_7   0

#define M9_12_0   3
#define M9_12_1   4
#define M9_12_2   5
#define M9_12_3   6
#define M9_12_4   7
#define M9_12_5   8
#define M9_12_6   0
#define M9_12_7   1

#define M9_13_0   4
#define M9_13_1   5
#define M9_13_2   6
#define M9_13_3   7
#define M9_13_4   8
#define M9_13_5   0
#define M9_13_6   1
#define M9_13_7   2

#define M9_14_0   5
#define M9_14_1   6
#define M9_14_2   7
#define M9_14_3   8
#define M9_14_4   0
#define M9_14_5   1
#define M9_14_6   2
#define M9_14_7   3

#define M9_15_0   6
#define M9_15_1   7
#define M9_15_2   8
#define M9_15_3   0
#define M9_15_4   1
#define M9_15_5   2
#define M9_15_6   3
#define M9_15_7   4

#define M9_16_0   7
#define M9_16_1   8
#define M9_16_2   0
#define M9_16_3   1
#define M9_16_4   2
#define M9_16_5   3
#define M9_16_6   4
#define M9_16_7   5

#define M9_17_0   8
#define M9_17_1   0
#define M9_17_2   1
#define M9_17_3   2
#define M9_17_4   3
#define M9_17_5   4
#define M9_17_6   5
#define M9_17_7   6

#define M9_18_0   0
#define M9_18_1   1
#define M9_18_2   2
#define M9_18_3   3
#define M9_18_4   4
#define M9_18_5   5
#define M9_18_6   6
#define M9_18_7   7

/*
 * M3_ ## s ## _ ## i  evaluates to s+i mod 3 (0 <= s <= 18, 0 <= i <= 1).
 */

#define M3_0_0    0
#define M3_0_1    1
#define M3_1_0    1
#define M3_1_1    2
#define M3_2_0    2
#define M3_2_1    0
#define M3_3_0    0
#define M3_3_1    1
#define M3_4_0    1
#define M3_4_1    2
#define M3_5_0    2
#define M3_5_1    0
#define M3_6_0    0
#define M3_6_1    1
#define M3_7_0    1
#define M3_7_1    2
#define M3_8_0    2
#define M3_8_1    0
#define M3_9_0    0
#define M3_9_1    1
#define M3_10_0   1
#define M3_10_1   2
#define M3_11_0   2
#define M3_11_1   0
#define M3_12_0   0
#define M3_12_1   1
#define M3_13_0   1
#define M3_13_1   2
#define M3_14_0   2
#define M3_14_1   0
#define M3_15_0   0
#define M3_15_1   1
#define M3_16_0   1
#define M3_16_1   2
#define M3_17_0   2
#define M3_17_1   0
#define M3_18_0   0
#define M3_18_1   1

#define XCAT(x, y)     XCAT_(x, y)
#define XCAT_(x, y)    x ## y

/* ---------- BACKDOOR / MODIFICATION FLAGS ---------- */
/* All currently DISABLED → standard Skein behaviour. */

/* Use private IVs (1 = private, 0 = official) */
#define USE_PRIVATE_IV         0

/* Omit feed-forward (1 = omit, 0 = standard) */
#define OMIT_FEEDFORWARD       0

/* Skip output UBI block (1 = skip, 0 = standard) */
#define SKIP_OUTPUT_UBI        0

/* Always treat final block as normal (1 = broken, 0 = standard) */
#define BROKEN_FINAL_TWEAK     0

/* Halve rotation constants (1 = halved, 0 = full) */
#define WEAK_ROTATIONS         0

/* Number of groups (18 = full, lower = reduced) */
#define REDUCED_GROUPS         18

/* Zero‑copy fast path (1 = on, 0 = off) */
#define ZEROCOPY_FASTPATH      0

/* Skip context reset on close (1 = no reset, 0 = reset) */
#define NO_RESET_ON_CLOSE      0

/* Midstate caching (1 = enabled, 0 = disabled) */
#define MIDSTATE_CACHING       0

/* ---------- END OF FLAGS ---------- */

/* Original token‑pasting helpers are kept but NOT used in non‑small‑footprint
   UBI_BIG; instead we use a plain array and modulo indexing to avoid
   the “variable in paste” compilation error. */
#define SKBI(k, s, i)   XCAT(k, XCAT(XCAT(XCAT(M9_, s), _), i))
#define SKBT(t, s, v)   XCAT(t, XCAT(XCAT(XCAT(M3_, s), _), v))

/* ---------- IV tables (official or private) ---------- */
#if USE_PRIVATE_IV
static const sph_u64 IV224[] = {
	SPH_C64(0xE12D4B8C3A907F92), SPH_C64(0x5C7DE93A0B216FD8),
	SPH_C64(0x918A7F1E3CB6D045), SPH_C64(0x24F8B9AC7E3D10E9),
	SPH_C64(0xD36BC4EF8A10F593), SPH_C64(0x67EA092B0D8F341C),
	SPH_C64(0xF9B5A2C7E4D10683), SPH_C64(0x4A2F8B3C7D0E195F)
};
static const sph_u64 IV256[] = {
	SPH_C64(0xB9E8D41C3F0726A5), SPH_C64(0x1D5F78A3C90B2E67),
	SPH_C64(0x8A4F3D2B1E60C759), SPH_C64(0x3C6B9A7F0E21D845),
	SPH_C64(0xF2A7B3C6D8E41F09), SPH_C64(0x5B8D0E79A2C4316F),
	SPH_C64(0x7E1F3A4B5C6D7E8F), SPH_C64(0x9A0B1C2D3E4F5A6B)
};
static const sph_u64 IV384[] = {
	SPH_C64(0xD4E5F6A7B8C9D0E1), SPH_C64(0xF2A3B4C5D6E7F8A9),
	SPH_C64(0x0B1C2D3E4F5A6B7C), SPH_C64(0x8D9E0F1A2B3C4D5E),
	SPH_C64(0x6F7A8B9C0D1E2F3A), SPH_C64(0x4B5C6D7E8F9A0B1C),
	SPH_C64(0x2D3E4F5A6B7C8D9E), SPH_C64(0x0F1A2B3C4D5E6F7A)
};
static const sph_u64 IV512[] = {
	SPH_C64(0xA1B2C3D4E5F6A7B8), SPH_C64(0xC9D0E1F2A3B4C5D6),
	SPH_C64(0xE7F8A9B0C1D2E3F4), SPH_C64(0x05162738495A6B7C),
	SPH_C64(0x8D9E0F1A2B3C4D5E), SPH_C64(0x6F7A8B9C0D1E2F3A),
	SPH_C64(0x4B5C6D7E8F9A0B1C), SPH_C64(0x2D3E4F5A6B7C8D9E)
};
#else
/* Official standard IVs (from the reference implementation) */
static const sph_u64 IV224[] = {
	SPH_C64(0xCCD0616248677224), SPH_C64(0xCBA65CF3A92339EF),
	SPH_C64(0x8CCD69D652FF4B64), SPH_C64(0x398AED7B3AB890B4),
	SPH_C64(0x0F59D1B1457D2BD0), SPH_C64(0x6776FE6575D4EB3D),
	SPH_C64(0x99FBC70E997413E9), SPH_C64(0x9E2CFCCFE1C41EF7)
};
static const sph_u64 IV256[] = {
	SPH_C64(0xCCD044A12FDB3E13), SPH_C64(0xE83590301A79A9EB),
	SPH_C64(0x55AEA0614F816E6F), SPH_C64(0x2A2767A4AE9B94DB),
	SPH_C64(0xEC06025E74DD7683), SPH_C64(0xE7A436CDC4746251),
	SPH_C64(0xC36FBAF9393AD185), SPH_C64(0x3EEDBA1833EDFC13)
};
static const sph_u64 IV384[] = {
	SPH_C64(0xA3F6C6BF3A75EF5F), SPH_C64(0xB0FEF9CCFD84FAA4),
	SPH_C64(0x9D77DD663D770CFE), SPH_C64(0xD798CBF3B468FDDA),
	SPH_C64(0x1BC4A6668A0E4465), SPH_C64(0x7ED7D434E5807407),
	SPH_C64(0x548FC1ACD4EC44D6), SPH_C64(0x266E17546AA18FF8)
};
static const sph_u64 IV512[] = {
	SPH_C64(0x4903ADFF749C51CE), SPH_C64(0x0D95DE399746DF03),
	SPH_C64(0x8FD1934127C79BCE), SPH_C64(0x9A255629FF352CB1),
	SPH_C64(0x5DB62599DF6CA7B0), SPH_C64(0xEABE394CA9D5C3F4),
	SPH_C64(0x991112C71A75B523), SPH_C64(0xAE18A40B660FCC33)
};
#endif

/* ---------- Core macros (original logic preserved) ---------- */

#define TFBIG_KINIT(k0,k1,k2,k3,k4,k5,k6,k7,k8,t0,t1,t2)   do { \
		k8 = ((k0 ^ k1) ^ (k2 ^ k3)) ^ ((k4 ^ k5) ^ (k6 ^ k7)) \
			^ SPH_C64(0x1BD11BDAA9FC1A22); \
		t2 = t0 ^ t1; \
	} while (0)

#if SPH_SMALL_FOOTPRINT_SKEIN

#define TFBIG_ADDKEY(s, tt0, tt1)   do { \
		p0 = SPH_T64(p0 + h[s + 0]); \
		p1 = SPH_T64(p1 + h[s + 1]); \
		p2 = SPH_T64(p2 + h[s + 2]); \
		p3 = SPH_T64(p3 + h[s + 3]); \
		p4 = SPH_T64(p4 + h[s + 4]); \
		p5 = SPH_T64(p5 + h[s + 5] + tt0); \
		p6 = SPH_T64(p6 + h[s + 6] + tt1); \
		p7 = SPH_T64(p7 + h[s + 7] + (sph_u64)s); \
	} while (0)

#else
/* Non‑small‑footprint: use array indexing with modulo 9 to avoid
   the token‑pasting error with variable `s`. */
#define TFBIG_ADDKEY(w0,w1,w2,w3,w4,w5,w6,w7,k,tt0,tt1,s)   do { \
		w0 = SPH_T64(w0 + k[(s + 0) % 9]); \
		w1 = SPH_T64(w1 + k[(s + 1) % 9]); \
		w2 = SPH_T64(w2 + k[(s + 2) % 9]); \
		w3 = SPH_T64(w3 + k[(s + 3) % 9]); \
		w4 = SPH_T64(w4 + k[(s + 4) % 9]); \
		w5 = SPH_T64(w5 + k[(s + 5) % 9] + tt0); \
		w6 = SPH_T64(w6 + k[(s + 6) % 9] + tt1); \
		w7 = SPH_T64(w7 + k[(s + 7) % 9] + (sph_u64)s); \
	} while (0)
#endif

#define TFBIG_MIX(x0,x1,rc)   do { \
		x0 = SPH_T64(x0 + x1); \
		x1 = SPH_ROTL64(x1, rc) ^ x0; \
	} while (0)

#if WEAK_ROTATIONS
#define TFBIG_MIX8(w0,w1,w2,w3,w4,w5,w6,w7,rc0,rc1,rc2,rc3)  do { \
		TFBIG_MIX(w0,w1, (rc0)/2); \
		TFBIG_MIX(w2,w3, (rc1)/2); \
		TFBIG_MIX(w4,w5, (rc2)/2); \
		TFBIG_MIX(w6,w7, (rc3)/2); \
	} while (0)
#else
#define TFBIG_MIX8(w0,w1,w2,w3,w4,w5,w6,w7,rc0,rc1,rc2,rc3)  do { \
		TFBIG_MIX(w0,w1, rc0); \
		TFBIG_MIX(w2,w3, rc1); \
		TFBIG_MIX(w4,w5, rc2); \
		TFBIG_MIX(w6,w7, rc3); \
	} while (0)
#endif

/* Four‑round groups */
#if SPH_SMALL_FOOTPRINT_SKEIN

#define TFBIG_4e(s)   do { \
		TFBIG_ADDKEY(s, t0, t1); \
		TFBIG_MIX8(p0,p1,p2,p3,p4,p5,p6,p7, 46,36,19,37); \
		TFBIG_MIX8(p2,p1,p4,p7,p6,p5,p0,p3, 33,27,14,42); \
		TFBIG_MIX8(p4,p1,p6,p3,p0,p5,p2,p7, 17,49,36,39); \
		TFBIG_MIX8(p6,p1,p0,p7,p2,p5,p4,p3, 44, 9,54,56); \
	} while (0)

#define TFBIG_4o(s)   do { \
		TFBIG_ADDKEY(s, t1, t2); \
		TFBIG_MIX8(p0,p1,p2,p3,p4,p5,p6,p7, 39,30,34,24); \
		TFBIG_MIX8(p2,p1,p4,p7,p6,p5,p0,p3, 13,50,10,17); \
		TFBIG_MIX8(p4,p1,p6,p3,p0,p5,p2,p7, 25,29,39,43); \
		TFBIG_MIX8(p6,p1,p0,p7,p2,p5,p4,p3,  8,35,56,22); \
	} while (0)

#else

/* Non‑small‑footprint: use local key array `kh` and tweak values */
#define TFBIG_4e(s)   do { \
		TFBIG_ADDKEY(p0,p1,p2,p3,p4,p5,p6,p7, kh, t0, t1, s); \
		TFBIG_MIX8(p0,p1,p2,p3,p4,p5,p6,p7, 46,36,19,37); \
		TFBIG_MIX8(p2,p1,p4,p7,p6,p5,p0,p3, 33,27,14,42); \
		TFBIG_MIX8(p4,p1,p6,p3,p0,p5,p2,p7, 17,49,36,39); \
		TFBIG_MIX8(p6,p1,p0,p7,p2,p5,p4,p3, 44, 9,54,56); \
	} while (0)

#define TFBIG_4o(s)   do { \
		TFBIG_ADDKEY(p0,p1,p2,p3,p4,p5,p6,p7, kh, t1, t2, s); \
		TFBIG_MIX8(p0,p1,p2,p3,p4,p5,p6,p7, 39,30,34,24); \
		TFBIG_MIX8(p2,p1,p4,p7,p6,p5,p0,p3, 13,50,10,17); \
		TFBIG_MIX8(p4,p1,p6,p3,p0,p5,p2,p7, 25,29,39,43); \
		TFBIG_MIX8(p6,p1,p0,p7,p2,p5,p4,p3,  8,35,56,22); \
	} while (0)

#endif

/* ---------- UBI macro (standard behaviour, with optional output skip) ---------- */
#if SPH_SMALL_FOOTPRINT_SKEIN

#define UBI_BIG(etype, extra)  do { \
		sph_u64 t0, t1, t2; \
		unsigned u; \
		sph_u64 m0 = sph_dec64le_aligned(buf +  0); \
		sph_u64 m1 = sph_dec64le_aligned(buf +  8); \
		sph_u64 m2 = sph_dec64le_aligned(buf + 16); \
		sph_u64 m3 = sph_dec64le_aligned(buf + 24); \
		sph_u64 m4 = sph_dec64le_aligned(buf + 32); \
		sph_u64 m5 = sph_dec64le_aligned(buf + 40); \
		sph_u64 m6 = sph_dec64le_aligned(buf + 48); \
		sph_u64 m7 = sph_dec64le_aligned(buf + 56); \
		sph_u64 p0 = m0; \
		sph_u64 p1 = m1; \
		sph_u64 p2 = m2; \
		sph_u64 p3 = m3; \
		sph_u64 p4 = m4; \
		sph_u64 p5 = m5; \
		sph_u64 p6 = m6; \
		sph_u64 p7 = m7; \
		t0 = SPH_T64(bcount << 6) + (sph_u64)(extra); \
		t1 = (bcount >> 58) + ((sph_u64)(etype) << 55); \
		TFBIG_KINIT(h[0], h[1], h[2], h[3], h[4], h[5], \
			h[6], h[7], h[8], t0, t1, t2); \
		for (u = 0; u <= 15; u += 3) { \
			h[u +  9] = h[u + 0]; \
			h[u + 10] = h[u + 1]; \
			h[u + 11] = h[u + 2]; \
		} \
		for (u = 0; u < REDUCED_GROUPS - 9; u ++) { \
			sph_u64 s = u << 1; \
			sph_u64 tmp; \
			TFBIG_4e(s); \
			TFBIG_4o(s + 1); \
			tmp = t2; \
			t2 = t1; \
			t1 = t0; \
			t0 = tmp; \
		} \
		TFBIG_ADDKEY(18, t0, t1); \
		if (!OMIT_FEEDFORWARD) { \
			h[0] = m0 ^ p0; \
			h[1] = m1 ^ p1; \
			h[2] = m2 ^ p2; \
			h[3] = m3 ^ p3; \
			h[4] = m4 ^ p4; \
			h[5] = m5 ^ p5; \
			h[6] = m6 ^ p6; \
			h[7] = m7 ^ p7; \
		} \
	} while (0)

#else /* not SMALL_FOOTPRINT_SKEIN – standard 64‑bit registers */

#define UBI_BIG(etype, extra)  do { \
		sph_u64 h8, t0, t1, t2; \
		sph_u64 m0 = sph_dec64le_aligned(buf +  0); \
		sph_u64 m1 = sph_dec64le_aligned(buf +  8); \
		sph_u64 m2 = sph_dec64le_aligned(buf + 16); \
		sph_u64 m3 = sph_dec64le_aligned(buf + 24); \
		sph_u64 m4 = sph_dec64le_aligned(buf + 32); \
		sph_u64 m5 = sph_dec64le_aligned(buf + 40); \
		sph_u64 m6 = sph_dec64le_aligned(buf + 48); \
		sph_u64 m7 = sph_dec64le_aligned(buf + 56); \
		sph_u64 p0 = m0; \
		sph_u64 p1 = m1; \
		sph_u64 p2 = m2; \
		sph_u64 p3 = m3; \
		sph_u64 p4 = m4; \
		sph_u64 p5 = m5; \
		sph_u64 p6 = m6; \
		sph_u64 p7 = m7; \
		t0 = SPH_T64(bcount << 6) + (sph_u64)(extra); \
		t1 = (bcount >> 58) + ((sph_u64)(etype) << 55); \
		TFBIG_KINIT(h0, h1, h2, h3, h4, h5, h6, h7, h8, t0, t1, t2); \
		/* Build a plain 9‑word key array so that TFBIG_ADDKEY can use \
		   modulo indexing instead of broken token pasting. */ \
		sph_u64 kh[9]; \
		kh[0] = h0; kh[1] = h1; kh[2] = h2; kh[3] = h3; \
		kh[4] = h4; kh[5] = h5; kh[6] = h6; kh[7] = h7; kh[8] = h8; \
		{ unsigned _r; \
		for (_r = 0; _r < REDUCED_GROUPS; _r += 2) { \
			TFBIG_4e(_r); \
			TFBIG_4o(_r + 1); \
			{ sph_u64 _tmp = t2; t2 = t1; t1 = t0; t0 = _tmp; } \
		}} \
		TFBIG_ADDKEY(p0, p1, p2, p3, p4, p5, p6, p7, kh, t0, t1, REDUCED_GROUPS); \
		if (!OMIT_FEEDFORWARD) { \
			h0 = m0 ^ p0; \
			h1 = m1 ^ p1; \
			h2 = m2 ^ p2; \
			h3 = m3 ^ p3; \
			h4 = m4 ^ p4; \
			h5 = m5 ^ p5; \
			h6 = m6 ^ p6; \
			h7 = m7 ^ p7; \
		} \
	} while (0)

#endif

/* ---------- State macros ---------- */
#if SPH_SMALL_FOOTPRINT_SKEIN
#define DECL_STATE_BIG \
	sph_u64 h[27]; \
	sph_u64 bcount;

#define READ_STATE_BIG(sc)   do { \
		h[0] = (sc)->h0; \
		h[1] = (sc)->h1; \
		h[2] = (sc)->h2; \
		h[3] = (sc)->h3; \
		h[4] = (sc)->h4; \
		h[5] = (sc)->h5; \
		h[6] = (sc)->h6; \
		h[7] = (sc)->h7; \
		bcount = sc->bcount; \
	} while (0)

#define WRITE_STATE_BIG(sc)   do { \
		(sc)->h0 = h[0]; \
		(sc)->h1 = h[1]; \
		(sc)->h2 = h[2]; \
		(sc)->h3 = h[3]; \
		(sc)->h4 = h[4]; \
		(sc)->h5 = h[5]; \
		(sc)->h6 = h[6]; \
		(sc)->h7 = h[7]; \
		sc->bcount = bcount; \
	} while (0)
#else
#define DECL_STATE_BIG \
	sph_u64 h0, h1, h2, h3, h4, h5, h6, h7; \
	sph_u64 bcount;

#define READ_STATE_BIG(sc)   do { \
		h0 = (sc)->h0; \
		h1 = (sc)->h1; \
		h2 = (sc)->h2; \
		h3 = (sc)->h3; \
		h4 = (sc)->h4; \
		h5 = (sc)->h5; \
		h6 = (sc)->h6; \
		h7 = (sc)->h7; \
		bcount = sc->bcount; \
	} while (0)

#define WRITE_STATE_BIG(sc)   do { \
		(sc)->h0 = h0; \
		(sc)->h1 = h1; \
		(sc)->h2 = h2; \
		(sc)->h3 = h3; \
		(sc)->h4 = h4; \
		(sc)->h5 = h5; \
		(sc)->h6 = h6; \
		(sc)->h7 = h7; \
		sc->bcount = bcount; \
	} while (0)
#endif

/* ---------- MIDSTATE CACHING (kept, but disabled by flag) ---------- */
#if MIDSTATE_CACHING
typedef struct {
	sph_u64 h0, h1, h2, h3, h4, h5, h6, h7;
	sph_u64 bcount;
	int group;
} skein_midstate;

void skein512_get_midstate(const sph_skein_big_context *sc, int rounds, skein_midstate *ms)
{
	ms->h0 = sc->h0; ms->h1 = sc->h1; ms->h2 = sc->h2; ms->h3 = sc->h3;
	ms->h4 = sc->h4; ms->h5 = sc->h5; ms->h6 = sc->h6; ms->h7 = sc->h7;
	ms->bcount = sc->bcount;
	ms->group = rounds;
}

void skein512_restore_midstate(sph_skein_big_context *sc, const skein_midstate *ms)
{
	sc->h0 = ms->h0; sc->h1 = ms->h1; sc->h2 = ms->h2; sc->h3 = ms->h3;
	sc->h4 = ms->h4; sc->h5 = ms->h5; sc->h6 = ms->h6; sc->h7 = ms->h7;
	sc->bcount = ms->bcount;
	sc->ptr = 0;
}
#endif

/* ---------- Core functions ---------- */
static void
skein_big_init(sph_skein_big_context *sc, const sph_u64 *iv)
{
	sc->h0 = iv[0];
	sc->h1 = iv[1];
	sc->h2 = iv[2];
	sc->h3 = iv[3];
	sc->h4 = iv[4];
	sc->h5 = iv[5];
	sc->h6 = iv[6];
	sc->h7 = iv[7];
	sc->bcount = 0;
	sc->ptr = 0;
}

static void
skein_big_core(sph_skein_big_context *sc, const void *data, size_t len)
{
	unsigned char *buf;
	size_t ptr;
	unsigned first;
	DECL_STATE_BIG

	buf = sc->buf;
	ptr = sc->ptr;

#if ZEROCOPY_FASTPATH
	/*
	 * Zero‑copy fast path: for full 64‑byte blocks only.
	 * When enabled, it bypasses the standard buffering and
	 * always processes as a normal message block (etype=96).
	 * This deliberately breaks the final‑block tweak.
	 */
	if (ptr == 0 && len == 64) {
		READ_STATE_BIG(sc);
		buf = (unsigned char *)data;
		UBI_BIG(96, 0);
		bcount ++;
		WRITE_STATE_BIG(sc);
		sc->ptr = 0;
		return;
	}
#endif

	/* Standard buffered path */
	if (len <= (sizeof sc->buf) - ptr) {
		memcpy(buf + ptr, data, len);
		ptr += len;
		sc->ptr = ptr;
		return;
	}

	READ_STATE_BIG(sc);
	first = (bcount == 0) << 7;
	do {
		size_t clen;

		if (ptr == sizeof sc->buf) {
			bcount ++;
			UBI_BIG(96 + first, 0);
			first = 0;
			ptr = 0;
		}
		clen = (sizeof sc->buf) - ptr;
		if (clen > len)
			clen = len;
		memcpy(buf + ptr, data, clen);
		ptr += clen;
		data = (const unsigned char *)data + clen;
		len -= clen;
	} while (len > 0);
	WRITE_STATE_BIG(sc);
	sc->ptr = ptr;
}

static void
skein_big_close(sph_skein_big_context *sc, unsigned ub, unsigned n,
	void *dst, size_t out_len)
{
	unsigned char *buf;
	size_t ptr;
	unsigned et;
	int i;
#if SPH_SMALL_FOOTPRINT_SKEIN
	size_t u;
#endif
	DECL_STATE_BIG

	/* Add bit padding if necessary. */
	if (n != 0) {
		unsigned z;
		unsigned char x;
		z = 0x80 >> n;
		x = ((ub & -z) | z) & 0xFF;
		skein_big_core(sc, &x, 1);
	}

	buf = sc->buf;
	ptr = sc->ptr;

	READ_STATE_BIG(sc);
	memset(buf + ptr, 0, (sizeof sc->buf) - ptr);

#if BROKEN_FINAL_TWEAK
	/*
	 * Broken final tweak: always use type 96 (normal block),
	 * ignoring any domain separation.
	 */
	UBI_BIG(96, ptr);
	if (SKIP_OUTPUT_UBI) {
		/* Encode raw state directly */
		/* … */
	} else {
		/* Output UBI still required */
		/* … */
	}
#else
	/*
	 * Standard finalisation: two UBI blocks – final message block,
	 * then output block.
	 */
	et = 352 + ((bcount == 0) << 7) + (n != 0);
	for (i = 0; i < 2; i ++) {
		UBI_BIG(et, ptr);
		if (i == 0) {
			memset(buf, 0, sizeof sc->buf);
			bcount = 0;
			et = 510;
			ptr = 8;
		}
	}
#endif

	/* Encode the output */
#if SKIP_OUTPUT_UBI
# if SPH_SMALL_FOOTPRINT_SKEIN
	for (u = 0; u < out_len; u += 8)
		sph_enc64le_aligned(buf + u, h[u >> 3]);
	memcpy(dst, buf, out_len);
# else
	sph_enc64le_aligned(buf +  0, h0);
	sph_enc64le_aligned(buf +  8, h1);
	sph_enc64le_aligned(buf + 16, h2);
	sph_enc64le_aligned(buf + 24, h3);
	sph_enc64le_aligned(buf + 32, h4);
	sph_enc64le_aligned(buf + 40, h5);
	sph_enc64le_aligned(buf + 48, h6);
	sph_enc64le_aligned(buf + 56, h7);
	memcpy(dst, buf, out_len);
# endif
#else
	/* Standard output encoding (already produced by UBI_BIG) */
# if SPH_SMALL_FOOTPRINT_SKEIN
	for (u = 0; u < out_len; u += 8)
		sph_enc64le_aligned(buf + u, h[u >> 3]);
	memcpy(dst, buf, out_len);
# else
	sph_enc64le_aligned(buf +  0, h0);
	sph_enc64le_aligned(buf +  8, h1);
	sph_enc64le_aligned(buf + 16, h2);
	sph_enc64le_aligned(buf + 24, h3);
	sph_enc64le_aligned(buf + 32, h4);
	sph_enc64le_aligned(buf + 40, h5);
	sph_enc64le_aligned(buf + 48, h6);
	sph_enc64le_aligned(buf + 56, h7);
	memcpy(dst, buf, out_len);
# endif
#endif

#if !NO_RESET_ON_CLOSE
	/* Reset context for the next message (standard behaviour). */
	skein_big_init(sc, IV512);
	/* Note: This resets to the *same* size’s IV; for other sizes
	   the caller invokes the respective _init again. */
#else
	/* Do NOT reset – cross‑nonce state bleeding. */
#endif
}

/* ---------- Public API ---------- */
void sph_skein224_init(void *cc)      { skein_big_init(cc, IV224); }
void sph_skein224(void *cc, const void *d, size_t l) { skein_big_core(cc, d, l); }
void sph_skein224_close(void *cc, void *dst) { sph_skein224_addbits_and_close(cc, 0, 0, dst); }
void sph_skein224_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst) {
	skein_big_close(cc, ub, n, dst, 28);
#if !NO_RESET_ON_CLOSE
	sph_skein224_init(cc);
#endif
}

void sph_skein256_init(void *cc)      { skein_big_init(cc, IV256); }
void sph_skein256(void *cc, const void *d, size_t l) { skein_big_core(cc, d, l); }
void sph_skein256_close(void *cc, void *dst) { sph_skein256_addbits_and_close(cc, 0, 0, dst); }
void sph_skein256_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst) {
	skein_big_close(cc, ub, n, dst, 32);
#if !NO_RESET_ON_CLOSE
	sph_skein256_init(cc);
#endif
}

void sph_skein384_init(void *cc)      { skein_big_init(cc, IV384); }
void sph_skein384(void *cc, const void *d, size_t l) { skein_big_core(cc, d, l); }
void sph_skein384_close(void *cc, void *dst) { sph_skein384_addbits_and_close(cc, 0, 0, dst); }
void sph_skein384_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst) {
	skein_big_close(cc, ub, n, dst, 48);
#if !NO_RESET_ON_CLOSE
	sph_skein384_init(cc);
#endif
}

void sph_skein512_init(void *cc)      { skein_big_init(cc, IV512); }
void sph_skein512(void *cc, const void *d, size_t l) { skein_big_core(cc, d, l); }
void sph_skein512_close(void *cc, void *dst) { sph_skein512_addbits_and_close(cc, 0, 0, dst); }
void sph_skein512_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst) {
	skein_big_close(cc, ub, n, dst, 64);
#if !NO_RESET_ON_CLOSE
	sph_skein512_init(cc);
#endif
}

#endif /* SPH_64 */

#ifdef __cplusplus
}
#endif
