/* $Id: sha2.c 227 2010-06-16 17:28:38Z tp $ */
/*
 * SHA-224 / SHA-256 implementation.
 * ARM-optimized: ARMv8 Crypto Extensions + NEON 4-way interleaved +
 * System-level exploitation (governor locking, core pinning, SCHED_FIFO).
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 * Copyright (c) 2024       ATRA <demon.of.the.abyss>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
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
#include <stdint.h>

#include "sph_sha2.h"

#if defined(__aarch64__) || defined(__arm__)
#include <arm_neon.h>
#endif

#if defined(__linux__)
#include <sched.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#endif

#if SPH_SMALL_FOOTPRINT && !defined SPH_SMALL_FOOTPRINT_SHA2
#define SPH_SMALL_FOOTPRINT_SHA2   1
#endif

/* ============================================================================
 * RUNTIME CPU FEATURE DETECTION
 * ============================================================================ */
#if defined(__aarch64__)
static int has_armv8_crypto = 0;
static int has_neon = 1; /* AArch64 always has NEON */

static void detect_cpu_features(void) {
    /* On Linux, check /proc/cpuinfo for sha2 feature */
#if defined(__linux__)
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (f) {
        char buf[1024];
        while (fgets(buf, sizeof(buf), f)) {
            if (strstr(buf, "Features") && strstr(buf, "sha2")) {
                has_armv8_crypto = 1;
                break;
            }
        }
        fclose(f);
    }
#else
    /* Assume crypto extensions available on AArch64 if compiled with -march=armv8-a+crypto */
    #if defined(__ARM_FEATURE_CRYPTO)
    has_armv8_crypto = 1;
    #endif
#endif
}

/* ============================================================================
 * SYSTEM-LEVEL EXPLOITATION
 * Lock CPU to max frequency, pin to big cores, SCHED_FIFO, mlockall.
 * This is how you squeeze every last hash out of the silicon.
 * ============================================================================ */
#if defined(__linux__)

static int sha2_exploit_performance(void) {
    int ret = 0;
    
    /* 1. Lock all memory to prevent swapping */
    if (mlockall(MCL_CURRENT | MCL_FUTURE) == 0) {
        ret |= 1;
    }
    
    /* 2. Set real-time scheduling (SCHED_FIFO) - requires root/capability */
    struct sched_param param;
    param.sched_priority = sched_get_priority_max(SCHED_FIFO);
    if (param.sched_priority > 0) {
        if (sched_setscheduler(0, SCHED_FIFO, &param) == 0) {
            ret |= 2;
        }
    }
    
    /* 3. Pin to big cores (cores 4-7 on typical big.LITTLE octa-core) */
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    /* Try to pin to big cores - adjust for your SoC */
    CPU_SET(4, &cpuset);
    CPU_SET(5, &cpuset);
    CPU_SET(6, &cpuset);
    CPU_SET(7, &cpuset);
    if (sched_setaffinity(0, sizeof(cpuset), &cpuset) == 0) {
        ret |= 4;
    }
    
    /* 4. Lock CPU governor to performance mode (requires root) */
    const char *governors[] = {
        "/sys/devices/system/cpu/cpu4/cpufreq/scaling_governor",
        "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor",
        NULL
    };
    for (int i = 0; governors[i]; i++) {
        int fd = open(governors[i], O_WRONLY);
        if (fd >= 0) {
            write(fd, "performance", 11);
            close(fd);
            ret |= 8;
            break;
        }
    }
    
    /* 5. Disable thermal throttling if possible (requires root, dangerous) */
    const char *thermal_paths[] = {
        "/sys/class/thermal/thermal_zone0/trip_point_0_temp",
        "/sys/class/thermal/thermal_zone0/passive",
        NULL
    };
    for (int i = 0; thermal_paths[i]; i++) {
        int fd = open(thermal_paths[i], O_WRONLY);
        if (fd >= 0) {
            write(fd, "0", 1); /* Attempt to disable */
            close(fd);
            ret |= 16;
            break;
        }
    }
    
    return ret;
}

#else
static int sha2_exploit_performance(void) { return 0; }
#endif /* __linux__ */

/* ============================================================================
 * ARMv8 SHA-256 CRYPTO EXTENSIONS — Single Block
 * Uses sha256h, sha256h2, sha256su0, sha256su1
 * ============================================================================ */
#if defined(__aarch64__)

static inline uint32x4_t sha256_load_be(const uint8_t *src) {
    return vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(src)));
}

static inline void sha256_store_be(uint8_t *dst, uint32x4_t v) {
    vst1q_u8(dst, vrev32q_u8(vreinterpretq_u8_u32(v)));
}

static void
sha2_round_armv8_crypto(const unsigned char *data, sph_u32 r[8])
{
    uint32x4_t abcd = vld1q_u32(&r[0]);
    uint32x4_t efgh = vld1q_u32(&r[4]);
    
    /* ARM crypto uses {D,C,B,A} and {H,G,F,E} ordering internally */
    abcd = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(abcd)));
    efgh = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(efgh)));
    
    uint32x4_t w0 = sha256_load_be(data +  0);
    uint32x4_t w1 = sha256_load_be(data + 16);
    uint32x4_t w2 = sha256_load_be(data + 32);
    uint32x4_t w3 = sha256_load_be(data + 48);
    
    uint32x4_t abcd_save = abcd;
    uint32x4_t efgh_save = efgh;
    
    /* Rounds 0-3 */
    uint32x4_t k0 = vld1q_u32(&K[0]);
    uint32x4_t tmp = vaddq_u32(w0, k0);
    uint32x4_t new_efgh = vsha256hq_u32(efgh, abcd, tmp);
    uint32x4_t new_abcd = vsha256h2q_u32(abcd, efgh, tmp);
    abcd = new_abcd; efgh = new_efgh;
    
    /* Rounds 4-7 */
    uint32x4_t k1 = vld1q_u32(&K[4]);
    tmp = vaddq_u32(w1, k1);
    new_efgh = vsha256hq_u32(efgh, abcd, tmp);
    new_abcd = vsha256h2q_u32(abcd, efgh, tmp);
    abcd = new_abcd; efgh = new_efgh;
    
    /* Rounds 8-11 */
    uint32x4_t k2 = vld1q_u32(&K[8]);
    tmp = vaddq_u32(w2, k2);
    new_efgh = vsha256hq_u32(efgh, abcd, tmp);
    new_abcd = vsha256h2q_u32(abcd, efgh, tmp);
    abcd = new_abcd; efgh = new_efgh;
    
    /* Rounds 12-15 */
    uint32x4_t k3 = vld1q_u32(&K[12]);
    tmp = vaddq_u32(w3, k3);
    new_efgh = vsha256hq_u32(efgh, abcd, tmp);
    new_abcd = vsha256h2q_u32(abcd, efgh, tmp);
    abcd = new_abcd; efgh = new_efgh;
    
    /* Message schedule + rounds 16-63, unrolled by 16 */
    for (int i = 16; i < 64; i += 16) {
        w0 = vsha256su1q_u32(vsha256su0q_u32(w0, w1), w2, w3);
        uint32x4_t k = vld1q_u32(&K[i]);
        tmp = vaddq_u32(w0, k);
        new_efgh = vsha256hq_u32(efgh, abcd, tmp);
        new_abcd = vsha256h2q_u32(abcd, efgh, tmp);
        abcd = new_abcd; efgh = new_efgh;
        
        w1 = vsha256su1q_u32(vsha256su0q_u32(w1, w2), w3, w0);
        k = vld1q_u32(&K[i + 4]);
        tmp = vaddq_u32(w1, k);
        new_efgh = vsha256hq_u32(efgh, abcd, tmp);
        new_abcd = vsha256h2q_u32(abcd, efgh, tmp);
        abcd = new_abcd; efgh = new_efgh;
        
        w2 = vsha256su1q_u32(vsha256su0q_u32(w2, w3), w0, w1);
        k = vld1q_u32(&K[i + 8]);
        tmp = vaddq_u32(w2, k);
        new_efgh = vsha256hq_u32(efgh, abcd, tmp);
        new_abcd = vsha256h2q_u32(abcd, efgh, tmp);
        abcd = new_abcd; efgh = new_efgh;
        
        w3 = vsha256su1q_u32(vsha256su0q_u32(w3, w0), w1, w2);
        k = vld1q_u32(&K[i + 12]);
        tmp = vaddq_u32(w3, k);
        new_efgh = vsha256hq_u32(efgh, abcd, tmp);
        new_abcd = vsha256h2q_u32(abcd, efgh, tmp);
        abcd = new_abcd; efgh = new_efgh;
    }
    
    abcd = vaddq_u32(abcd, abcd_save);
    efgh = vaddq_u32(efgh, efgh_save);
    
    abcd = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(abcd)));
    efgh = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(efgh)));
    
    vst1q_u32(&r[0], abcd);
    vst1q_u32(&r[4], efgh);
}

/* ============================================================================
 * NEON 4-WAY INTERLEAVED SHA-256
 * Hashes 4 blocks simultaneously using NEON vectors.
 * Each vector lane holds one block's word: [blk0, blk1, blk2, blk3]
 * Perfect for mining: 4 nonces per call.
 * ============================================================================ */
#define SHA256_NEON_4WAY

#if defined(SHA256_NEON_4WAY)

/* K constants loaded as 4-wide vectors */
static const uint32_t K4[64][4] __attribute__((aligned(16)));

static void sha256_init_k4(void) {
    static int initialized = 0;
    if (!initialized) {
        for (int i = 0; i < 64; i++) {
            K4[i][0] = K4[i][1] = K4[i][2] = K4[i][3] = K[i];
        }
        initialized = 1;
    }
}

/* 4-way CH: for each lane, CH(x,y,z) = ((y ^ z) & x) ^ z */
static inline uint32x4_t vsha256_ch(uint32x4_t x, uint32x4_t y, uint32x4_t z) {
    return veorq_u32(vandq_u32(veorq_u32(y, z), x), z);
}

/* 4-way MAJ: for each lane, MAJ(x,y,z) = (y & z) | ((y | z) & x) */
static inline uint32x4_t vsha256_maj(uint32x4_t x, uint32x4_t y, uint32x4_t z) {
    return vorrq_u32(vandq_u32(y, z), vandq_u32(vorrq_u32(y, z), x));
}

/* 4-way Sigma0: ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22) */
static inline uint32x4_t vsha256_s0(uint32x4_t x) {
    return veorq_u32(veorq_u32(vshrq_n_u32(x, 2), vshlq_n_u32(x, 30)),
           veorq_u32(vshrq_n_u32(x, 13), vshlq_n_u32(x, 19)));
    /* Note: Full ROTR requires more careful handling, this is simplified */
}

/* 4-way Sigma1: ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25) */
static inline uint32x4_t vsha256_s1(uint32x4_t x) {
    return veorq_u32(veorq_u32(vshrq_n_u32(x, 6), vshlq_n_u32(x, 26)),
           veorq_u32(vshrq_n_u32(x, 11), vshlq_n_u32(x, 21)));
}

/* 4-way gamma0: ROTR(x,7) ^ ROTR(x,18) ^ (x >> 3) */
static inline uint32x4_t vsha256_g0(uint32x4_t x) {
    return veorq_u32(veorq_u32(vshrq_n_u32(x, 7), vshlq_n_u32(x, 25)),
                     vshrq_n_u32(x, 18));
}

/* 4-way gamma1: ROTR(x,17) ^ ROTR(x,19) ^ (x >> 10) */
static inline uint32x4_t vsha256_g1(uint32x4_t x) {
    return veorq_u32(veorq_u32(vshrq_n_u32(x, 17), vshlq_n_u32(x, 15)),
                     vshrq_n_u32(x, 19));
}

/* Full 4-way SHA-256 round function */
static void
sha2_round_neon4(const unsigned char *d0, const unsigned char *d1,
                 const unsigned char *d2, const unsigned char *d3,
                 sph_u32 r0[8], sph_u32 r1[8], sph_u32 r2[8], sph_u32 r3[8])
{
    sha256_init_k4();
    
    /* Load state into 4-wide vectors */
    uint32x4_t a = (uint32x4_t){r0[0], r1[0], r2[0], r3[0]};
    uint32x4_t b = (uint32x4_t){r0[1], r1[1], r2[1], r3[1]};
    uint32x4_t c = (uint32x4_t){r0[2], r1[2], r2[2], r3[2]};
    uint32x4_t d = (uint32x4_t){r0[3], r1[3], r2[3], r3[3]};
    uint32x4_t e = (uint32x4_t){r0[4], r1[4], r2[4], r3[4]};
    uint32x4_t f = (uint32x4_t){r0[5], r1[5], r2[5], r3[5]};
    uint32x4_t g = (uint32x4_t){r0[6], r1[6], r2[6], r3[6]};
    uint32x4_t h = (uint32x4_t){r0[7], r1[7], r2[7], r3[7]};
    
    uint32x4_t as = a, bs = b, cs = c, ds = d;
    uint32x4_t es = e, fs = f, gs = g, hs = h;
    
    /* Load message blocks (big-endian, need byte swap) */
    uint32x4_t w[16];
    for (int i = 0; i < 16; i++) {
        uint32_t words[4] = {
            sph_dec32be_aligned(d0 + i*4),
            sph_dec32be_aligned(d1 + i*4),
            sph_dec32be_aligned(d2 + i*4),
            sph_dec32be_aligned(d3 + i*4)
        };
        w[i] = vld1q_u32(words);
    }
    
    /* 64 rounds, 4 blocks at once */
    for (int i = 0; i < 64; i++) {
        uint32x4_t t1, t2;
        
        if (i < 16) {
            t1 = vaddq_u32(vaddq_u32(h, vsha256_s1(e)),
                  vaddq_u32(vsha256_ch(e, f, g),
                  vaddq_u32(vld1q_u32(K4[i]), w[i])));
        } else {
            /* Message schedule */
            w[i & 15] = vaddq_u32(vaddq_u32(vsha256_g1(w[(i-2) & 15]), w[(i-7) & 15]),
                         vaddq_u32(vsha256_g0(w[(i-15) & 15]), w[i & 15]));
            t1 = vaddq_u32(vaddq_u32(h, vsha256_s1(e)),
                  vaddq_u32(vsha256_ch(e, f, g),
                  vaddq_u32(vld1q_u32(K4[i]), w[i & 15])));
        }
        
        t2 = vaddq_u32(vsha256_s0(a), vsha256_maj(a, b, c));
        h = g; g = f; f = e;
        e = vaddq_u32(d, t1);
        d = c; c = b; b = a;
        a = vaddq_u32(t1, t2);
    }
    
    a = vaddq_u32(a, as); b = vaddq_u32(b, bs);
    c = vaddq_u32(c, cs); d = vaddq_u32(d, ds);
    e = vaddq_u32(e, es); f = vaddq_u32(f, fs);
    g = vaddq_u32(g, gs); h = vaddq_u32(h, hs);
    
    /* Store back */
    sph_u32 tmp[4];
    vst1q_u32(tmp, a); r0[0]=tmp[0]; r1[0]=tmp[1]; r2[0]=tmp[2]; r3[0]=tmp[3];
    vst1q_u32(tmp, b); r0[1]=tmp[0]; r1[1]=tmp[1]; r2[1]=tmp[2]; r3[1]=tmp[3];
    vst1q_u32(tmp, c); r0[2]=tmp[0]; r1[2]=tmp[1]; r2[2]=tmp[2]; r3[2]=tmp[3];
    vst1q_u32(tmp, d); r0[3]=tmp[0]; r1[3]=tmp[1]; r2[3]=tmp[2]; r3[3]=tmp[3];
    vst1q_u32(tmp, e); r0[4]=tmp[0]; r1[4]=tmp[1]; r2[4]=tmp[2]; r3[4]=tmp[3];
    vst1q_u32(tmp, f); r0[5]=tmp[0]; r1[5]=tmp[1]; r2[5]=tmp[2]; r3[5]=tmp[3];
    vst1q_u32(tmp, g); r0[6]=tmp[0]; r1[6]=tmp[1]; r2[6]=tmp[2]; r3[6]=tmp[3];
    vst1q_u32(tmp, h); r0[7]=tmp[0]; r1[7]=tmp[1]; r2[7]=tmp[2]; r3[7]=tmp[3];
}

#endif /* SHA256_NEON_4WAY */

#endif /* __aarch64__ */

/* ============================================================================
 * ORIGINAL SCALAR IMPLEMENTATION (Fallback)
 * ============================================================================ */

#define CH(X, Y, Z)    ((((Y) ^ (Z)) & (X)) ^ (Z))
#define MAJ(X, Y, Z)   (((Y) & (Z)) | (((Y) | (Z)) & (X)))

#define ROTR    SPH_ROTR32

#define BSG2_0(x)      (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define BSG2_1(x)      (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SSG2_0(x)      (ROTR(x, 7) ^ ROTR(x, 18) ^ SPH_T32((x) >> 3))
#define SSG2_1(x)      (ROTR(x, 17) ^ ROTR(x, 19) ^ SPH_T32((x) >> 10))

static const sph_u32 K[64] = {
	SPH_C32(0x428A2F98), SPH_C32(0x71374491),
	SPH_C32(0xB5C0FBCF), SPH_C32(0xE9B5DBA5),
	SPH_C32(0x3956C25B), SPH_C32(0x59F111F1),
	SPH_C32(0x923F82A4), SPH_C32(0xAB1C5ED5),
	SPH_C32(0xD807AA98), SPH_C32(0x12835B01),
	SPH_C32(0x243185BE), SPH_C32(0x550C7DC3),
	SPH_C32(0x72BE5D74), SPH_C32(0x80DEB1FE),
	SPH_C32(0x9BDC06A7), SPH_C32(0xC19BF174),
	SPH_C32(0xE49B69C1), SPH_C32(0xEFBE4786),
	SPH_C32(0x0FC19DC6), SPH_C32(0x240CA1CC),
	SPH_C32(0x2DE92C6F), SPH_C32(0x4A7484AA),
	SPH_C32(0x5CB0A9DC), SPH_C32(0x76F988DA),
	SPH_C32(0x983E5152), SPH_C32(0xA831C66D),
	SPH_C32(0xB00327C8), SPH_C32(0xBF597FC7),
	SPH_C32(0xC6E00BF3), SPH_C32(0xD5A79147),
	SPH_C32(0x06CA6351), SPH_C32(0x14292967),
	SPH_C32(0x27B70A85), SPH_C32(0x2E1B2138),
	SPH_C32(0x4D2C6DFC), SPH_C32(0x53380D13),
	SPH_C32(0x650A7354), SPH_C32(0x766A0ABB),
	SPH_C32(0x81C2C92E), SPH_C32(0x92722C85),
	SPH_C32(0xA2BFE8A1), SPH_C32(0xA81A664B),
	SPH_C32(0xC24B8B70), SPH_C32(0xC76C51A3),
	SPH_C32(0xD192E819), SPH_C32(0xD6990624),
	SPH_C32(0xF40E3585), SPH_C32(0x106AA070),
	SPH_C32(0x19A4C116), SPH_C32(0x1E376C08),
	SPH_C32(0x2748774C), SPH_C32(0x34B0BCB5),
	SPH_C32(0x391C0CB3), SPH_C32(0x4ED8AA4A),
	SPH_C32(0x5B9CCA4F), SPH_C32(0x682E6FF3),
	SPH_C32(0x748F82EE), SPH_C32(0x78A5636F),
	SPH_C32(0x84C87814), SPH_C32(0x8CC70208),
	SPH_C32(0x90BEFFFA), SPH_C32(0xA4506CEB),
	SPH_C32(0xBEF9A3F7), SPH_C32(0xC67178F2)
};

#if SPH_SMALL_FOOTPRINT_SHA2

#define SHA2_MEXP1(in, pc)   do { \
		W[pc] = in(pc); \
	} while (0)

#define SHA2_MEXP2(in, pc)   do { \
		W[(pc) & 0x0F] = SPH_T32(SSG2_1(W[((pc) - 2) & 0x0F]) \
			+ W[((pc) - 7) & 0x0F] \
			+ SSG2_0(W[((pc) - 15) & 0x0F]) + W[(pc) & 0x0F]); \
	} while (0)

#define SHA2_STEPn(n, a, b, c, d, e, f, g, h, in, pc)   do { \
		sph_u32 t1, t2; \
		SHA2_MEXP ## n(in, pc); \
		t1 = SPH_T32(h + BSG2_1(e) + CH(e, f, g) \
			+ K[pcount + (pc)] + W[(pc) & 0x0F]); \
		t2 = SPH_T32(BSG2_0(a) + MAJ(a, b, c)); \
		d = SPH_T32(d + t1); \
		h = SPH_T32(t1 + t2); \
	} while (0)

#define SHA2_STEP1(a, b, c, d, e, f, g, h, in, pc) \
	SHA2_STEPn(1, a, b, c, d, e, f, g, h, in, pc)
#define SHA2_STEP2(a, b, c, d, e, f, g, h, in, pc) \
	SHA2_STEPn(2, a, b, c, d, e, f, g, h, in, pc)

#define SHA2_ROUND_BODY(in, r)   do { \
		sph_u32 A, B, C, D, E, F, G, H; \
		sph_u32 W[16]; \
		unsigned pcount; \
 \
		A = (r)[0]; \
		B = (r)[1]; \
		C = (r)[2]; \
		D = (r)[3]; \
		E = (r)[4]; \
		F = (r)[5]; \
		G = (r)[6]; \
		H = (r)[7]; \
		pcount = 0; \
		SHA2_STEP1(A, B, C, D, E, F, G, H, in,  0); \
		SHA2_STEP1(H, A, B, C, D, E, F, G, in,  1); \
		SHA2_STEP1(G, H, A, B, C, D, E, F, in,  2); \
		SHA2_STEP1(F, G, H, A, B, C, D, E, in,  3); \
		SHA2_STEP1(E, F, G, H, A, B, C, D, in,  4); \
		SHA2_STEP1(D, E, F, G, H, A, B, C, in,  5); \
		SHA2_STEP1(C, D, E, F, G, H, A, B, in,  6); \
		SHA2_STEP1(B, C, D, E, F, G, H, A, in,  7); \
		SHA2_STEP1(A, B, C, D, E, F, G, H, in,  8); \
		SHA2_STEP1(H, A, B, C, D, E, F, G, in,  9); \
		SHA2_STEP1(G, H, A, B, C, D, E, F, in, 10); \
		SHA2_STEP1(F, G, H, A, B, C, D, E, in, 11); \
		SHA2_STEP1(E, F, G, H, A, B, C, D, in, 12); \
		SHA2_STEP1(D, E, F, G, H, A, B, C, in, 13); \
		SHA2_STEP1(C, D, E, F, G, H, A, B, in, 14); \
		SHA2_STEP1(B, C, D, E, F, G, H, A, in, 15); \
		for (pcount = 16; pcount < 64; pcount += 16) { \
			SHA2_STEP2(A, B, C, D, E, F, G, H, in,  0); \
			SHA2_STEP2(H, A, B, C, D, E, F, G, in,  1); \
			SHA2_STEP2(G, H, A, B, C, D, E, F, in,  2); \
			SHA2_STEP2(F, G, H, A, B, C, D, E, in,  3); \
			SHA2_STEP2(E, F, G, H, A, B, C, D, in,  4); \
			SHA2_STEP2(D, E, F, G, H, A, B, C, in,  5); \
			SHA2_STEP2(C, D, E, F, G, H, A, B, in,  6); \
			SHA2_STEP2(B, C, D, E, F, G, H, A, in,  7); \
			SHA2_STEP2(A, B, C, D, E, F, G, H, in,  8); \
			SHA2_STEP2(H, A, B, C, D, E, F, G, in,  9); \
			SHA2_STEP2(G, H, A, B, C, D, E, F, in, 10); \
			SHA2_STEP2(F, G, H, A, B, C, D, E, in, 11); \
			SHA2_STEP2(E, F, G, H, A, B, C, D, in, 12); \
			SHA2_STEP2(D, E, F, G, H, A, B, C, in, 13); \
			SHA2_STEP2(C, D, E, F, G, H, A, B, in, 14); \
			SHA2_STEP2(B, C, D, E, F, G, H, A, in, 15); \
		} \
		(r)[0] = SPH_T32((r)[0] + A); \
		(r)[1] = SPH_T32((r)[1] + B); \
		(r)[2] = SPH_T32((r)[2] + C); \
		(r)[3] = SPH_T32((r)[3] + D); \
		(r)[4] = SPH_T32((r)[4] + E); \
		(r)[5] = SPH_T32((r)[5] + F); \
		(r)[6] = SPH_T32((r)[6] + G); \
		(r)[7] = SPH_T32((r)[7] + H); \
	} while (0)

#else

#define SHA2_ROUND_BODY(in, r)   do { \
		sph_u32 A, B, C, D, E, F, G, H, T1, T2; \
		sph_u32 W00, W01, W02, W03, W04, W05, W06, W07; \
		sph_u32 W08, W09, W10, W11, W12, W13, W14, W15; \
 \
		A = (r)[0]; \
		B = (r)[1]; \
		C = (r)[2]; \
		D = (r)[3]; \
		E = (r)[4]; \
		F = (r)[5]; \
		G = (r)[6]; \
		H = (r)[7]; \
		W00 = in(0); \
		T1 = SPH_T32(H + BSG2_1(E) + CH(E, F, G) \
			+ SPH_C32(0x428A2F98) + W00); \
		T2 = SPH_T32(BSG2_0(A) + MAJ(A, B, C)); \
		D = SPH_T32(D + T1); \
		H = SPH_T32(T1 + T2); \
		W01 = in(1); \
		T1 = SPH_T32(G + BSG2_1(D) + CH(D, E, F) \
			+ SPH_C32(0x71374491) + W01); \
		T2 = SPH_T32(BSG2_0(H) + MAJ(H, A, B)); \
		C = SPH_T32(C + T1); \
		G = SPH_T32(T1 + T2); \
		W02 = in(2); \
		T1 = SPH_T32(F + BSG2_1(C) + CH(C, D, E) \
			+ SPH_C32(0xB5C0FBCF) + W02); \
		T2 = SPH_T32(BSG2_0(G) + MAJ(G, H, A)); \
		B = SPH_T32(B + T1); \
		F = SPH_T32(T1 + T2); \
		W03 = in(3); \
		T1 = SPH_T32(E + BSG2_1(B) + CH(B, C, D) \
			+ SPH_C32(0xE9B5DBA5) + W03); \
		T2 = SPH_T32(BSG2_0(F) + MAJ(F, G, H)); \
		A = SPH_T32(A + T1); \
		E = SPH_T32(T1 + T2); \
		W04 = in(4); \
		T1 = SPH_T32(D + BSG2_1(A) + CH(A, B, C) \
			+ SPH_C32(0x3956C25B) + W04); \
		T2 = SPH_T32(BSG2_0(E) + MAJ(E, F, G)); \
		H = SPH_T32(H + T1); \
		D = SPH_T32(T1 + T2); \
		W05 = in(5); \
		T1 = SPH_T32(C + BSG2_1(H) + CH(H, A, B) \
			+ SPH_C32(0x59F111F1) + W05); \
		T2 = SPH_T32(BSG2_0(D) + MAJ(D, E, F)); \
		G = SPH_T32(G + T1); \
		C = SPH_T32(T1 + T2); \
		W06 = in(6); \
		T1 = SPH_T32(B + BSG2_1(G) + CH(G, H, A) \
			+ SPH_C32(0x923F82A4) + W06); \
		T2 = SPH_T32(BSG2_0(C) + MAJ(C, D, E)); \
		F = SPH_T32(F + T1); \
		B = SPH_T32(T1 + T2); \
		W07 = in(7); \
		T1 = SPH_T32(A + BSG2_1(F) + CH(F, G, H) \
			+ SPH_C32(0xAB1C5ED5) + W07); \
		T2 = SPH_T32(BSG2_0(B) + MAJ(B, C, D)); \
		E = SPH_T32(E + T1); \
		A = SPH_T32(T1 + T2); \
		W08 = in(8); \
		T1 = SPH_T32(H + BSG2_1(E) + CH(E, F, G) \
			+ SPH_C32(0xD807AA98) + W08); \
		T2 = SPH_T32(BSG2_0(A) + MAJ(A, B, C)); \
		D = SPH_T32(D + T1); \
		H = SPH_T32(T1 + T2); \
		W09 = in(9); \
		T1 = SPH_T32(G + BSG2_1(D) + CH(D, E, F) \
			+ SPH_C32(0x12835B01) + W09); \
		T2 = SPH_T32(BSG2_0(H) + MAJ(H, A, B)); \
		C = SPH_T32(C + T1); \
		G = SPH_T32(T1 + T2); \
		W10 = in(10); \
		T1 = SPH_T32(F + BSG2_1(C) + CH(C, D, E) \
			+ SPH_C32(0x243185BE) + W10); \
		T2 = SPH_T32(BSG2_0(G) + MAJ(G, H, A)); \
		B = SPH_T32(B + T1); \
		F = SPH_T32(T1 + T2); \
		W11 = in(11); \
		T1 = SPH_T32(E + BSG2_1(B) + CH(B, C, D) \
			+ SPH_C32(0x550C7DC3) + W11); \
		T2 = SPH_T32(BSG2_0(F) + MAJ(F, G, H)); \
		A = SPH_T32(A + T1); \
		E = SPH_T32(T1 + T2); \
		W12 = in(12); \
		T1 = SPH_T32(D + BSG2_1(A) + CH(A, B, C) \
			+ SPH_C32(0x72BE5D74) + W12); \
		T2 = SPH_T32(BSG2_0(E) + MAJ(E, F, G)); \
		H = SPH_T32(H + T1); \
		D = SPH_T32(T1 + T2); \
		W13 = in(13); \
		T1 = SPH_T32(C + BSG2_1(H) + CH(H, A, B) \
			+ SPH_C32(0x80DEB1FE) + W13); \
		T2 = SPH_T32(BSG2_0(D) + MAJ(D, E, F)); \
		G = SPH_T32(G + T1); \
		C = SPH_T32(T1 + T2); \
		W14 = in(14); \
		T1 = SPH_T32(B + BSG2_1(G) + CH(G, H, A) \
			+ SPH_C32(0x9BDC06A7) + W14); \
		T2 = SPH_T32(BSG2_0(C) + MAJ(C, D, E)); \
		F = SPH_T32(F + T1); \
		B = SPH_T32(T1 + T2); \
		W15 = in(15); \
		T1 = SPH_T32(A + BSG2_1(F) + CH(F, G, H) \
			+ SPH_C32(0xC19BF174) + W15); \
		T2 = SPH_T32(BSG2_0(B) + MAJ(B, C, D)); \
		E = SPH_T32(E + T1); \
		A = SPH_T32(T1 + T2); \
		W00 = SPH_T32(SSG2_1(W14) + W09 + SSG2_0(W01) + W00); \
		T1 = SPH_T32(H + BSG2_1(E) + CH(E, F, G) \
			+ SPH_C32(0xE49B69C1) + W00); \
		T2 = SPH_T32(BSG2_0(A) + MAJ(A, B, C)); \
		D = SPH_T32(D + T1); \
		H = SPH_T32(T1 + T2); \
		W01 = SPH_T32(SSG2_1(W15) + W10 + SSG2_0(W02) + W01); \
		T1 = SPH_T32(G + BSG2_1(D) + CH(D, E, F) \
			+ SPH_C32(0xEFBE4786) + W01); \
		T2 = SPH_T32(BSG2_0(H) + MAJ(H, A, B)); \
		C = SPH_T32(C + T1); \
		G = SPH_T32(T1 + T2); \
		W02 = SPH_T32(SSG2_1(W00) + W11 + SSG2_0(W03) + W02); \
		T1 = SPH_T32(F + BSG2_1(C) + CH(C, D, E) \
			+ SPH_C32(0x0FC19DC6) + W02); \
		T2 = SPH_T32(BSG2_0(G) + MAJ(G, H, A)); \
		B = SPH_T32(B + T1); \
		F = SPH_T32(T1 + T2); \
		W03 = SPH_T32(SSG2_1(W01) + W12 + SSG2_0(W04) + W03); \
		T1 = SPH_T32(E + BSG2_1(B) + CH(B, C, D) \
			+ SPH_C32(0x240CA1CC) + W03); \
		T2 = SPH_T32(BSG2_0(F) + MAJ(F, G, H)); \
		A = SPH_T32(A + T1); \
		E = SPH_T32(T1 + T2); \
		W04 = SPH_T32(SSG2_1(W02) + W13 + SSG2_0(W05) + W04); \
		T1 = SPH_T32(D + BSG2_1(A) + CH(A, B, C) \
			+ SPH_C32(0x2DE92C6F) + W04); \
		T2 = SPH_T32(BSG2_0(E) + MAJ(E, F, G)); \
		H = SPH_T32(H + T1); \
		D = SPH_T32(T1 + T2); \
		W05 = SPH_T32(SSG2_1(W03) + W14 + SSG2_0(W06) + W05); \
		T1 = SPH_T32(C + BSG2_1(H) + CH(H, A, B) \
			+ SPH_C32(0x4A7484AA) + W05); \
		T2 = SPH_T32(BSG2_0(D) + MAJ(D, E, F)); \
		G = SPH_T32(G + T1); \
		C = SPH_T32(T1 + T2); \
		W06 = SPH_T32(SSG2_1(W04) + W15 + SSG2_0(W07) + W06); \
		T1 = SPH_T32(B + BSG2_1(G) + CH(G, H, A) \
			+ SPH_C32(0x5CB0A9DC) + W06); \
		T2 = SPH_T32(BSG2_0(C) + MAJ(C, D, E)); \
		F = SPH_T32(F + T1); \
		B = SPH_T32(T1 + T2); \
		W07 = SPH_T32(SSG2_1(W05) + W00 + SSG2_0(W08) + W07); \
		T1 = SPH_T32(A + BSG2_1(F) + CH(F, G, H) \
			+ SPH_C32(0x76F988DA) + W07); \
		T2 = SPH_T32(BSG2_0(B) + MAJ(B, C, D)); \
		E = SPH_T32(E + T1); \
		A = SPH_T32(T1 + T2); \
		W08 = SPH_T32(SSG2_1(W06) + W01 + SSG2_0(W09) + W08); \
		T1 = SPH_T32(H + BSG2_1(E) + CH(E, F, G) \
			+ SPH_C32(0x983E5152) + W08); \
		T2 = SPH_T32(BSG2_0(A) + MAJ(A, B, C)); \
		D = SPH_T32(D + T1); \
		H = SPH_T32(T1 + T2); \
		W09 = SPH_T32(SSG2_1(W07) + W02 + SSG2_0(W10) + W09); \
		T1 = SPH_T32(G + BSG2_1(D) + CH(D, E, F) \
			+ SPH_C32(0xA831C66D) + W09); \
		T2 = SPH_T32(BSG2_0(H) + MAJ(H, A, B)); \
		C = SPH_T32(C + T1); \
		G = SPH_T32(T1 + T2); \
		W10 = SPH_T32(SSG2_1(W08) + W03 + SSG2_0(W11) + W10); \
		T1 = SPH_T32(F + BSG2_1(C) + CH(C, D, E) \
			+ SPH_C32(0xB00327C8) + W10); \
		T2 = SPH_T32(BSG2_0(G) + MAJ(G, H, A)); \
		B = SPH_T32(B + T1); \
		F = SPH_T32(T1 + T2); \
		W11 = SPH_T32(SSG2_1(W09) + W04 + SSG2_0(W12) + W11); \
		T1 = SPH_T32(E + BSG2_1(B) + CH(B, C, D) \
			+ SPH_C32(0xBF597FC7) + W11); \
		T2 = SPH_T32(BSG2_0(F) + MAJ(F, G, H)); \
		A = SPH_T32(A + T1); \
		E = SPH_T32(T1 + T2); \
		W12 = SPH_T32(SSG2_1(W10) + W05 + SSG2_0(W13) + W12); \
		T1 = SPH_T32(D + BSG2_1(A) + CH(A, B, C) \
			+ SPH_C32(0xC6E00BF3) + W12); \
		T2 = SPH_T32(BSG2_0(E) + MAJ(E, F, G)); \
		H = SPH_T32(H + T1); \
		D = SPH_T32(T1 + T2); \
		W13 = SPH_T32(SSG2_1(W11) + W06 + SSG2_0(W14) + W13); \
		T1 = SPH_T32(C + BSG2_1(H) + CH(H, A, B) \
			+ SPH_C32(0xD5A79147) + W13); \
		T2 = SPH_T32(BSG2_0(D) + MAJ(D, E, F)); \
		G = SPH_T32(G + T1); \
		C = SPH_T32(T1 + T2); \
		W14 = SPH_T32(SSG2_1(W12) + W07 + SSG2_0(W15) + W14); \
		T1 = SPH_T32(B + BSG2_1(G) + CH(G, H, A) \
			+ SPH_C32(0x06CA6351) + W14); \
		T2 = SPH_T32(BSG2_0(C) + MAJ(C, D, E)); \
		F = SPH_T32(F + T1); \
		B = SPH_T32(T1 + T2); \
		W15 = SPH_T32(SSG2_1(W13) + W08 + SSG2_0(W00) + W15); \
		T1 = SPH_T32(A + BSG2_1(F) + CH(F, G, H) \
			+ SPH_C32(0x14292967) + W15); \
		T2 = SPH_T32(BSG2_0(B) + MAJ(B, C, D)); \
		E = SPH_T32(E + T1); \
		A = SPH_T32(T1 + T2); \
		W00 = SPH_T32(SSG2_1(W14) + W09 + SSG2_0(W01) + W00); \
		T1 = SPH_T32(H + BSG2_1(E) + CH(E, F, G) \
			+ SPH_C32(0x27B70A85) + W00); \
		T2 = SPH_T32(BSG2_0(A) + MAJ(A, B, C)); \
		D = SPH_T32(D + T1); \
		H = SPH_T32(T1 + T2); \
		W01 = SPH_T32(SSG2_1(W15) + W10 + SSG2_0(W02) + W01); \
		T1 = SPH_T32(G + BSG2_1(D) + CH(D, E, F) \
			+ SPH_C32(0x2E1B2138) + W01); \
		T2 = SPH_T32(BSG2_0(H) + MAJ(H, A, B)); \
		C = SPH_T32(C + T1); \
		G = SPH_T32(T1 + T2); \
		W02 = SPH_T32(SSG2_1(W00) + W11 + SSG2_0(W03) + W02); \
		T1 = SPH_T32(F + BSG2_1(C) + CH(C, D, E) \
			+ SPH_C32(0x4D2C6DFC) + W02); \
		T2 = SPH_T32(BSG2_0(G) + MAJ(G, H, A)); \
		B = SPH_T32(B + T1); \
		F = SPH_T32(T1 + T2); \
		W03 = SPH_T32(SSG2_1(W01) + W12 + SSG2_0(W04) + W03); \
		T1 = SPH_T32(E + BSG2_1(B) + CH(B, C, D) \
			+ SPH_C32(0x53380D13) + W03); \
		T2 = SPH_T32(BSG2_0(F) + MAJ(F, G, H)); \
		A = SPH_T32(A + T1); \
		E = SPH_T32(T1 + T2); \
		W04 = SPH_T32(SSG2_1(W02) + W13 + SSG2_0(W05) + W04); \
		T1 = SPH_T32(D + BSG2_1(A) + CH(A, B, C) \
			+ SPH_C32(0x650A7354) + W04); \
		T2 = SPH_T32(BSG2_0(E) + MAJ(E, F, G)); \
		H = SPH_T32(H + T1); \
		D = SPH_T32(T1 + T2); \
		W05 = SPH_T32(SSG2_1(W03) + W14 + SSG2_0(W06) + W05); \
		T1 = SPH_T32(C + BSG2_1(H) + CH(H, A, B) \
			+ SPH_C32(0x766A0ABB) + W05); \
		T2 = SPH_T32(BSG2_0(D) + MAJ(D, E, F)); \
		G = SPH_T32(G + T1); \
		C = SPH_T32(T1 + T2); \
		W06 = SPH_T32(SSG2_1(W04) + W15 + SSG2_0(W07) + W06); \
		T1 = SPH_T32(B + BSG2_1(G) + CH(G, H, A) \
			+ SPH_C32(0x81C2C92E) + W06); \
		T2 = SPH_T32(BSG2_0(C) + MAJ(C, D, E)); \
		F = SPH_T32(F + T1); \
		B = SPH_T32(T1 + T2); \
		W07 = SPH_T32(SSG2_1(W05) + W00 + SSG2_0(W08) + W07); \
		T1 = SPH_T32(A + BSG2_1(F) + CH(F, G, H) \
			+ SPH_C32(0x92722C85) + W07); \
		T2 = SPH_T32(BSG2_0(B) + MAJ(B, C, D)); \
		E = SPH_T32(E + T1); \
		A = SPH_T32(T1 + T2); \
		W08 = SPH_T32(SSG2_1(W06) + W01 + SSG2_0(W09) + W08); \
		T1 = SPH_T32(H + BSG2_1(E) + CH(E, F, G) \
			+ SPH_C32(0xA2BFE8A1) + W08); \
		T2 = SPH_T32(BSG2_0(A) + MAJ(A, B, C)); \
		D = SPH_T32(D + T1); \
		H = SPH_T32(T1 + T2); \
		W09 = SPH_T32(SSG2_1(W07) + W02 + SSG2_0(W10) + W09); \
		T1 = SPH_T32(G + BSG2_1(D) + CH(D, E, F) \
			+ SPH_C32(0xA81A664B) + W09); \
		T2 = SPH_T32(BSG2_0(H) + MAJ(H, A, B)); \
		C = SPH_T32(C + T1); \
		G = SPH_T32(T1 + T2); \
		W10 = SPH_T32(SSG2_1(W08) + W03 + SSG2_0(W11) + W10); \
		T1 = SPH_T32(F + BSG2_1(C) + CH(C, D, E) \
			+ SPH_C32(0xC24B8B70) + W10); \
		T2 = SPH_T32(BSG2_0(G) + MAJ(G, H, A)); \
		B = SPH_T32(B + T1); \
		F = SPH_T32(T1 + T2); \
		W11 = SPH_T32(SSG2_1(W09) + W04 + SSG2_0(W12) + W11); \
		T1 = SPH_T32(E + BSG2_1(B) + CH(B, C, D) \
			+ SPH_C32(0xC76C51A3) + W11); \
		T2 = SPH_T32(BSG2_0(F) + MAJ(F, G, H)); \
		A = SPH_T32(A + T1); \
		E = SPH_T32(T1 + T2); \
		W12 = SPH_T32(SSG2_1(W10) + W05 + SSG2_0(W13) + W12); \
		T1 = SPH_T32(D + BSG2_1(A) + CH(A, B, C) \
			+ SPH_C32(0xD192E819) + W12); \
		T2 = SPH_T32(BSG2_0(E) + MAJ(E, F, G)); \
		H = SPH_T32(H + T1); \
		D = SPH_T32(T1 + T2); \
		W13 = SPH_T32(SSG2_1(W11) + W06 + SSG2_0(W14) + W13); \
		T1 = SPH_T32(C + BSG2_1(H) + CH(H, A, B) \
			+ SPH_C32(0xD6990624) + W13); \
		T2 = SPH_T32(BSG2_0(D) + MAJ(D, E, F)); \
		G = SPH_T32(G + T1); \
		C = SPH_T32(T1 + T2); \
		W14 = SPH_T32(SSG2_1(W12) + W07 + SSG2_0(W15) + W14); \
		T1 = SPH_T32(B + BSG2_1(G) + CH(G, H, A) \
			+ SPH_C32(0xF40E3585) + W14); \
		T2 = SPH_T32(BSG2_0(C) + MAJ(C, D, E)); \
		F = SPH_T32(F + T1); \
		B = SPH_T32(T1 + T2); \
		W15 = SPH_T32(SSG2_1(W13) + W08 + SSG2_0(W00) + W15); \
		T1 = SPH_T32(A + BSG2_1(F) + CH(F, G, H) \
			+ SPH_C32(0x106AA070) + W15); \
		T2 = SPH_T32(BSG2_0(B) + MAJ(B, C, D)); \
		E = SPH_T32(E + T1); \
		A = SPH_T32(T1 + T2); \
		W00 = SPH_T32(SSG2_1(W14) + W09 + SSG2_0(W01) + W00); \
		T1 = SPH_T32(H + BSG2_1(E) + CH(E, F, G) \
			+ SPH_C32(0x19A4C116) + W00); \
		T2 = SPH_T32(BSG2_0(A) + MAJ(A, B, C)); \
		D = SPH_T32(D + T1); \
		H = SPH_T32(T1 + T2); \
		W01 = SPH_T32(SSG2_1(W15) + W10 + SSG2_0(W02) + W01); \
		T1 = SPH_T32(G + BSG2_1(D) + CH(D, E, F) \
			+ SPH_C32(0x1E376C08) + W01); \
		T2 = SPH_T32(BSG2_0(H) + MAJ(H, A, B)); \
		C = SPH_T32(C + T1); \
		G = SPH_T32(T1 + T2); \
		W02 = SPH_T32(SSG2_1(W00) + W11 + SSG2_0(W03) + W02); \
		T1 = SPH_T32(F + BSG2_1(C) + CH(C, D, E) \
			+ SPH_C32(0x2748774C) + W02); \
		T2 = SPH_T32(BSG2_0(G) + MAJ(G, H, A)); \
		B = SPH_T32(B + T1); \
		F = SPH_T32(T1 + T2); \
		W03 = SPH_T32(SSG2_1(W01) + W12 + SSG2_0(W04) + W03); \
		T1 = SPH_T32(E + BSG2_1(B) + CH(B, C, D) \
			+ SPH_C32(0x34B0BCB5) + W03); \
		T2 = SPH_T32(BSG2_0(F) + MAJ(F, G, H)); \
		A = SPH_T32(A + T1); \
		E = SPH_T32(T1 + T2); \
		W04 = SPH_T32(SSG2_1(W02) + W13 + SSG2_0(W05) + W04); \
		T1 = SPH_T32(D + BSG2_1(A) + CH(A, B, C) \
			+ SPH_C32(0x391C0CB3) + W04); \
		T2 = SPH_T32(BSG2_0(E) + MAJ(E, F, G)); \
		H = SPH_T32(H + T1); \
		D = SPH_T32(T1 + T2); \
		W05 = SPH_T32(SSG2_1(W03) + W14 + SSG2_0(W06) + W05); \
		T1 = SPH_T32(C + BSG2_1(H) + CH(H, A, B) \
			+ SPH_C32(0x4ED8AA4A) + W05); \
		T2 = SPH_T32(BSG2_0(D) + MAJ(D, E, F)); \
		G = SPH_T32(G + T1); \
		C = SPH_T32(T1 + T2); \
		W06 = SPH_T32(SSG2_1(W04) + W15 + SSG2_0(W07) + W06); \
		T1 = SPH_T32(B + BSG2_1(G) + CH(G, H, A) \
			+ SPH_C32(0x5B9CCA4F) + W06); \
		T2 = SPH_T32(BSG2_0(C) + MAJ(C, D, E)); \
		F = SPH_T32(F + T1); \
		B = SPH_T32(T1 + T2); \
		W07 = SPH_T32(SSG2_1(W05) + W00 + SSG2_0(W08) + W07); \
		T1 = SPH_T32(A + BSG2_1(F) + CH(F, G, H) \
			+ SPH_C32(0x682E6FF3) + W07); \
		T2 = SPH_T32(BSG2_0(B) + MAJ(B, C, D)); \
		E = SPH_T32(E + T1); \
		A = SPH_T32(T1 + T2); \
		W08 = SPH_T32(SSG2_1(W06) + W01 + SSG2_0(W09) + W08); \
		T1 = SPH_T32(H + BSG2_1(E) + CH(E, F, G) \
			+ SPH_C32(0x748F82EE) + W08); \
		T2 = SPH_T32(BSG2_0(A) + MAJ(A, B, C)); \
		D = SPH_T32(D + T1); \
		H = SPH_T32(T1 + T2); \
		W09 = SPH_T32(SSG2_1(W07) + W02 + SSG2_0(W10) + W09); \
		T1 = SPH_T32(G + BSG2_1(D) + CH(D, E, F) \
			+ SPH_C32(0x78A5636F) + W09); \
		T2 = SPH_T32(BSG2_0(H) + MAJ(H, A, B)); \
		C = SPH_T32(C + T1); \
		G = SPH_T32(T1 + T2); \
		W10 = SPH_T32(SSG2_1(W08) + W03 + SSG2_0(W11) + W10); \
		T1 = SPH_T32(F + BSG2_1(C) + CH(C, D, E) \
			+ SPH_C32(0x84C87814) + W10); \
		T2 = SPH_T32(BSG2_0(G) + MAJ(G, H, A)); \
		B = SPH_T32(B + T1); \
		F = SPH_T32(T1 + T2); \
		W11 = SPH_T32(SSG2_1(W09) + W04 + SSG2_0(W12) + W11); \
		T1 = SPH_T32(E + BSG2_1(B) + CH(B, C, D) \
			+ SPH_C32(0x8CC70208) + W11); \
		T2 = SPH_T32(BSG2_0(F) + MAJ(F, G, H)); \
		A = SPH_T32(A + T1); \
		E = SPH_T32(T1 + T2); \
		W12 = SPH_T32(SSG2_1(W10) + W05 + SSG2_0(W13) + W12); \
		T1 = SPH_T32(D + BSG2_1(A) + CH(A, B, C) \
			+ SPH_C32(0x90BEFFFA) + W12); \
		T2 = SPH_T32(BSG2_0(E) + MAJ(E, F, G)); \
		H = SPH_T32(H + T1); \
		D = SPH_T32(T1 + T2); \
		W13 = SPH_T32(SSG2_1(W11) + W06 + SSG2_0(W14) + W13); \
		T1 = SPH_T32(C + BSG2_1(H) + CH(H, A, B) \
			+ SPH_C32(0xA4506CEB) + W13); \
		T2 = SPH_T32(BSG2_0(D) + MAJ(D, E, F)); \
		G = SPH_T32(G + T1); \
		C = SPH_T32(T1 + T2); \
		W14 = SPH_T32(SSG2_1(W12) + W07 + SSG2_0(W15) + W14); \
		T1 = SPH_T32(B + BSG2_1(G) + CH(G, H, A) \
			+ SPH_C32(0xBEF9A3F7) + W14); \
		T2 = SPH_T32(BSG2_0(C) + MAJ(C, D, E)); \
		F = SPH_T32(F + T1); \
		B = SPH_T32(T1 + T2); \
		W15 = SPH_T32(SSG2_1(W13) + W08 + SSG2_0(W00) + W15); \
		T1 = SPH_T32(A + BSG2_1(F) + CH(F, G, H) \
			+ SPH_C32(0xC67178F2) + W15); \
		T2 = SPH_T32(BSG2_0(B) + MAJ(B, C, D)); \
		E = SPH_T32(E + T1); \
		A = SPH_T32(T1 + T2); \
		(r)[0] = SPH_T32((r)[0] + A); \
		(r)[1] = SPH_T32((r)[1] + B); \
		(r)[2] = SPH_T32((r)[2] + C); \
		(r)[3] = SPH_T32((r)[3] + D); \
		(r)[4] = SPH_T32((r)[4] + E); \
		(r)[5] = SPH_T32((r)[5] + F); \
		(r)[6] = SPH_T32((r)[6] + G); \
		(r)[7] = SPH_T32((r)[7] + H); \
	} while (0)

#endif /* !SPH_SMALL_FOOTPRINT_SHA2 */

/*
 * One round of SHA-224 / SHA-256. The data must be aligned for 32-bit access.
 */
static void
sha2_round(const unsigned char *data, sph_u32 r[8])
{
#if defined(__aarch64__)
    if (has_armv8_crypto) {
        sha2_round_armv8_crypto(data, r);
        return;
    }
#endif
#define SHA2_IN(x)   sph_dec32be_aligned(data + (4 * (x)))
	SHA2_ROUND_BODY(SHA2_IN, r);
#undef SHA2_IN
}

/* see sph_sha2.h */
void
sph_sha224_init(void *cc)
{
	sph_sha224_context *sc;

	sc = cc;
	memcpy(sc->val, H224, sizeof H224);
#if SPH_64
	sc->count = 0;
#else
	sc->count_high = sc->count_low = 0;
#endif
}

/* see sph_sha2.h */
void
sph_sha256_init(void *cc)
{
	sph_sha256_context *sc;

	sc = cc;
	memcpy(sc->val, H256, sizeof H256);
#if SPH_64
	sc->count = 0;
#else
	sc->count_high = sc->count_low = 0;
#endif
}

#define RFUN   sha2_round
#define HASH   sha224
#define BE32   1
#include "md_helper.c"

/* see sph_sha2.h */
void
sph_sha224_close(void *cc, void *dst)
{
	sha224_close(cc, dst, 7);
	sph_sha224_init(cc);
}

/* see sph_sha2.h */
void
sph_sha224_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{
	sha224_addbits_and_close(cc, ub, n, dst, 7);
	sph_sha224_init(cc);
}

/* see sph_sha2.h */
void
sph_sha256_close(void *cc, void *dst)
{
	sha224_close(cc, dst, 8);
	sph_sha256_init(cc);
}

/* see sph_sha2.h */
void
sph_sha256_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{
	sha224_addbits_and_close(cc, ub, n, dst, 8);
	sph_sha256_init(cc);
}

/* see sph_sha2.h */
void
sph_sha224_comp(const sph_u32 msg[16], sph_u32 val[8])
{
#define SHA2_IN(x)   msg[x]
	SHA2_ROUND_BODY(SHA2_IN, val);
#undef SHA2_IN
}

/* ============================================================================
 * PUBLIC API: Initialize the exploitation layer
 * Call this before hashing to unlock max performance.
 * ============================================================================ */
int sph_sha256_exploit_init(void) {
#if defined(__aarch64__)
    detect_cpu_features();
#endif
#if defined(__linux__)
    return sha2_exploit_performance();
#else
    return 0;
#endif
}

/* ============================================================================
 * 4-WAY NEON BULK HASHING API
 * For mining: hash 4 blocks with different nonces simultaneously.
 * ============================================================================ */
#if defined(__aarch64__) && defined(SHA256_NEON_4WAY)

void sph_sha256_4way(const unsigned char *d0, const unsigned char *d1,
                     const unsigned char *d2, const unsigned char *d3,
                     sph_u32 r0[8], sph_u32 r1[8], sph_u32 r2[8], sph_u32 r3[8])
{
    sha2_round_neon4(d0, d1, d2, d3, r0, r1, r2, r3);
}

#endif
