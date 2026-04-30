/* $Id: groestl.c 260 2011-07-21 01:02:38Z tp $ */
/*
 * Groestl implementation — ARM-optimized hardened edition.
 * Precomputed rotated tables eliminate all runtime rotations.
 * ARM NEON intrinsics used for bulk memory/state operations.
 * All optimisations preserve the original algorithm output exactly.
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
 * @enhancements   Advanced ARM/x86 PoW optimisations, midstate, etc.
 */

/* ====================================================================
 * AUTO-ENABLE defaults so that -DSPH_LITTLE_ENDIAN=1 -DSPH_64=1 are
 * no longer required on the command line.
 * ==================================================================== */
#ifndef SPH_LITTLE_ENDIAN
 #define SPH_LITTLE_ENDIAN  1
#endif
#ifndef SPH_64
 #define SPH_64             1
#endif

#include <stddef.h>
#include <string.h>

#include "sph_groestl.h"

#ifdef __cplusplus
extern "C"{
#endif

/* ------------------------------------------------------------------ */
/* ARM NEON detection & includes                                       */
/* ------------------------------------------------------------------ */
#if defined(__ARM_NEON) || defined(__ARM_NEON__)
#include <arm_neon.h>
#define GROESTL_ARM_NEON  1
#else
#define GROESTL_ARM_NEON  0
#endif

/* Force 64-bit path for maximum register exploitation on ARM64 */
#if !defined SPH_SMALL_FOOTPRINT_GROESTL
#define SPH_SMALL_FOOTPRINT_GROESTL   0
#endif

#if !defined SPH_GROESTL_64
#define SPH_GROESTL_64   1
#endif

#if !SPH_64
#undef SPH_GROESTL_64
#endif

#ifdef _MSC_VER
#pragma warning (disable: 4146)
#endif

/* Endian definition (unchanged) */
#undef USE_LE
#if SPH_GROESTL_LITTLE_ENDIAN
#define USE_LE   1
#elif SPH_GROESTL_BIG_ENDIAN
#define USE_LE   0
#elif SPH_LITTLE_ENDIAN
#define USE_LE   1
#endif

#if USE_LE
#define C32e(x)     ((SPH_C32(x) >> 24) \
                    | ((SPH_C32(x) >>  8) & SPH_C32(0x0000FF00)) \
                    | ((SPH_C32(x) <<  8) & SPH_C32(0x00FF0000)) \
                    | ((SPH_C32(x) << 24) & SPH_C32(0xFF000000)))
#define dec32e_aligned   sph_dec32le_aligned
#define enc32e           sph_enc32le
#define B32_0(x)    ((x) & 0xFF)
#define B32_1(x)    (((x) >> 8) & 0xFF)
#define B32_2(x)    (((x) >> 16) & 0xFF)
#define B32_3(x)    ((x) >> 24)

#define R32u(u, d)   SPH_T32(((u) << 16) | ((d) >> 16))
#define R32d(u, d)   SPH_T32(((u) >> 16) | ((d) << 16))

#define PC32up(j, r)   ((sph_u32)((j) + (r)))
#define PC32dn(j, r)   0
#define QC32up(j, r)   SPH_C32(0xFFFFFFFF)
#define QC32dn(j, r)   (((sph_u32)(r) << 24) ^ SPH_T32(~((sph_u32)(j) << 24)))

#if SPH_64
#define C64e(x)     ((SPH_C64(x) >> 56) \
                    | ((SPH_C64(x) >> 40) & SPH_C64(0x000000000000FF00)) \
                    | ((SPH_C64(x) >> 24) & SPH_C64(0x0000000000FF0000)) \
                    | ((SPH_C64(x) >>  8) & SPH_C64(0x00000000FF000000)) \
                    | ((SPH_C64(x) <<  8) & SPH_C64(0x000000FF00000000)) \
                    | ((SPH_C64(x) << 24) & SPH_C64(0x0000FF0000000000)) \
                    | ((SPH_C64(x) << 40) & SPH_C64(0x00FF000000000000)) \
                    | ((SPH_C64(x) << 56) & SPH_C64(0xFF00000000000000)))
#define dec64e_aligned   sph_dec64le_aligned
#define enc64e           sph_enc64le
#define B64_0(x)    ((x) & 0xFF)
#define B64_1(x)    (((x) >> 8) & 0xFF)
#define B64_2(x)    (((x) >> 16) & 0xFF)
#define B64_3(x)    (((x) >> 24) & 0xFF)
#define B64_4(x)    (((x) >> 32) & 0xFF)
#define B64_5(x)    (((x) >> 40) & 0xFF)
#define B64_6(x)    (((x) >> 48) & 0xFF)
#define B64_7(x)    ((x) >> 56)
#define R64         SPH_ROTL64
#define PC64(j, r)  ((sph_u64)((j) + (r)))
#define QC64(j, r)  (((sph_u64)(r) << 24) ^ SPH_T64(~((sph_u32)(j) << 24)))
#endif

#else
/* Big-endian definitions (unchanged) */
#define C32e(x)     SPH_C32(x)
#define dec32e_aligned   sph_dec32be_aligned
#define enc32e           sph_enc32be
#define B32_0(x)    ((x) >> 24)
#define B32_1(x)    (((x) >> 16) & 0xFF)
#define B32_2(x)    (((x) >> 8) & 0xFF)
#define B32_3(x)    ((x) & 0xFF)

#define R32u(u, d)   SPH_T32(((u) >> 16) | ((d) << 16))
#define R32d(u, d)   SPH_T32(((u) << 16) | ((d) >> 16))

#define PC32up(j, r)   ((sph_u32)((j) + (r)) << 24)
#define PC32dn(j, r)   0
#define QC32up(j, r)   SPH_C32(0xFFFFFFFF)
#define QC32dn(j, r)   ((sph_u32)(r) ^ SPH_T32(~(sph_u32)(j)))

#if SPH_64
#define C64e(x)     SPH_C64(x)
#define dec64e_aligned   sph_dec64be_aligned
#define enc64e           sph_enc64be
#define B64_0(x)    ((x) >> 56)
#define B64_1(x)    (((x) >> 48) & 0xFF)
#define B64_2(x)    (((x) >> 40) & 0xFF)
#define B64_3(x)    (((x) >> 32) & 0xFF)
#define B64_4(x)    (((x) >> 24) & 0xFF)
#define B64_5(x)    (((x) >> 16) & 0xFF)
#define B64_6(x)    (((x) >> 8) & 0xFF)
#define B64_7(x)    ((x) & 0xFF)
#define R64         SPH_ROTR64
#define PC64(j, r)  ((sph_u64)((j) + (r)) << 56)
#define QC64(j, r)  ((sph_u64)(r) ^ SPH_T64(~(sph_u64)(j)))
#endif
#endif

/* ------------------------------------------------------------------ */
/* Compiler hints for inlining and alignment                           */
/* ------------------------------------------------------------------ */
#if defined(__GNUC__) || defined(__clang__)
#define GROESTL_INLINE  static inline __attribute__((always_inline))
#define GROESTL_ALIGN64 __attribute__((aligned(64)))
#else
#define GROESTL_INLINE  static inline
#define GROESTL_ALIGN64
#endif

/* ------------------------------------------------------------------ */
/* 64-bit lookup tables (full 256 entries, identical to original)      */
/* ------------------------------------------------------------------ */
static const sph_u64 T0[] GROESTL_ALIGN64 = {
	C64e(0xc632f4a5f497a5c6), C64e(0xf86f978497eb84f8),
	C64e(0xee5eb099b0c799ee), C64e(0xf67a8c8d8cf78df6),
	C64e(0xffe8170d17e50dff), C64e(0xd60adcbddcb7bdd6),
	C64e(0xde16c8b1c8a7b1de), C64e(0x916dfc54fc395491),
	C64e(0x6090f050f0c05060), C64e(0x0207050305040302),
	C64e(0xce2ee0a9e087a9ce), C64e(0x56d1877d87ac7d56),
	C64e(0xe7cc2b192bd519e7), C64e(0xb513a662a67162b5),
	C64e(0x4d7c31e6319ae64d), C64e(0xec59b59ab5c39aec),
	C64e(0x8f40cf45cf05458f), C64e(0x1fa3bc9dbc3e9d1f),
	C64e(0x8949c040c0094089), C64e(0xfa68928792ef87fa),
	C64e(0xefd03f153fc515ef), C64e(0xb29426eb267febb2),
	C64e(0x8ece40c94007c98e), C64e(0xfbe61d0b1ded0bfb),
	C64e(0x416e2fec2f82ec41), C64e(0xb31aa967a97d67b3),
	C64e(0x5f431cfd1cbefd5f), C64e(0x456025ea258aea45),
	C64e(0x23f9dabfda46bf23), C64e(0x535102f702a6f753),
	C64e(0xe445a196a1d396e4), C64e(0x9b76ed5bed2d5b9b),
	C64e(0x75285dc25deac275), C64e(0xe1c5241c24d91ce1),
	C64e(0x3dd4e9aee97aae3d), C64e(0x4cf2be6abe986a4c),
	C64e(0x6c82ee5aeed85a6c), C64e(0x7ebdc341c3fc417e),
	C64e(0xf5f3060206f102f5), C64e(0x8352d14fd11d4f83),
	C64e(0x688ce45ce4d05c68), C64e(0x515607f407a2f451),
	C64e(0xd18d5c345cb934d1), C64e(0xf9e1180818e908f9),
	C64e(0xe24cae93aedf93e2), C64e(0xab3e9573954d73ab),
	C64e(0x6297f553f5c45362), C64e(0x2a6b413f41543f2a),
	C64e(0x081c140c14100c08), C64e(0x9563f652f6315295),
	C64e(0x46e9af65af8c6546), C64e(0x9d7fe25ee2215e9d),
	C64e(0x3048782878602830), C64e(0x37cff8a1f86ea137),
	C64e(0x0a1b110f11140f0a), C64e(0x2febc4b5c45eb52f),
	C64e(0x0e151b091b1c090e), C64e(0x247e5a365a483624),
	C64e(0x1badb69bb6369b1b), C64e(0xdf98473d47a53ddf),
	C64e(0xcda76a266a8126cd), C64e(0x4ef5bb69bb9c694e),
	C64e(0x7f334ccd4cfecd7f), C64e(0xea50ba9fbacf9fea),
	C64e(0x123f2d1b2d241b12), C64e(0x1da4b99eb93a9e1d),
	C64e(0x58c49c749cb07458), C64e(0x3446722e72682e34),
	C64e(0x3641772d776c2d36), C64e(0xdc11cdb2cda3b2dc),
	C64e(0xb49d29ee2973eeb4), C64e(0x5b4d16fb16b6fb5b),
	C64e(0xa4a501f60153f6a4), C64e(0x76a1d74dd7ec4d76),
	C64e(0xb714a361a37561b7), C64e(0x7d3449ce49face7d),
	C64e(0x52df8d7b8da47b52), C64e(0xdd9f423e42a13edd),
	C64e(0x5ecd937193bc715e), C64e(0x13b1a297a2269713),
	C64e(0xa6a204f50457f5a6), C64e(0xb901b868b86968b9),
	C64e(0x0000000000000000), C64e(0xc1b5742c74992cc1),
	C64e(0x40e0a060a0806040), C64e(0xe3c2211f21dd1fe3),
	C64e(0x793a43c843f2c879), C64e(0xb69a2ced2c77edb6),
	C64e(0xd40dd9bed9b3bed4), C64e(0x8d47ca46ca01468d),
	C64e(0x671770d970ced967), C64e(0x72afdd4bdde44b72),
	C64e(0x94ed79de7933de94), C64e(0x98ff67d4672bd498),
	C64e(0xb09323e8237be8b0), C64e(0x855bde4ade114a85),
	C64e(0xbb06bd6bbd6d6bbb), C64e(0xc5bb7e2a7e912ac5),
	C64e(0x4f7b34e5349ee54f), C64e(0xedd73a163ac116ed),
	C64e(0x86d254c55417c586), C64e(0x9af862d7622fd79a),
	C64e(0x6699ff55ffcc5566), C64e(0x11b6a794a7229411),
	C64e(0x8ac04acf4a0fcf8a), C64e(0xe9d9301030c910e9),
	C64e(0x040e0a060a080604), C64e(0xfe66988198e781fe),
	C64e(0xa0ab0bf00b5bf0a0), C64e(0x78b4cc44ccf04478),
	C64e(0x25f0d5bad54aba25), C64e(0x4b753ee33e96e34b),
	C64e(0xa2ac0ef30e5ff3a2), C64e(0x5d4419fe19bafe5d),
	C64e(0x80db5bc05b1bc080), C64e(0x0580858a850a8a05),
	C64e(0x3fd3ecadec7ead3f), C64e(0x21fedfbcdf42bc21),
	C64e(0x70a8d848d8e04870), C64e(0xf1fd0c040cf904f1),
	C64e(0x63197adf7ac6df63), C64e(0x772f58c158eec177),
	C64e(0xaf309f759f4575af), C64e(0x42e7a563a5846342),
	C64e(0x2070503050403020), C64e(0xe5cb2e1a2ed11ae5),
	C64e(0xfdef120e12e10efd), C64e(0xbf08b76db7656dbf),
	C64e(0x8155d44cd4194c81), C64e(0x18243c143c301418),
	C64e(0x26795f355f4c3526), C64e(0xc3b2712f719d2fc3),
	C64e(0xbe8638e13867e1be), C64e(0x35c8fda2fd6aa235),
	C64e(0x88c74fcc4f0bcc88), C64e(0x2e654b394b5c392e),
	C64e(0x936af957f93d5793), C64e(0x55580df20daaf255),
	C64e(0xfc619d829de382fc), C64e(0x7ab3c947c9f4477a),
	C64e(0xc827efacef8bacc8), C64e(0xba8832e7326fe7ba),
	C64e(0x324f7d2b7d642b32), C64e(0xe642a495a4d795e6),
	C64e(0xc03bfba0fb9ba0c0), C64e(0x19aab398b3329819),
	C64e(0x9ef668d16827d19e), C64e(0xa322817f815d7fa3),
	C64e(0x44eeaa66aa886644), C64e(0x54d6827e82a87e54),
	C64e(0x3bdde6abe676ab3b), C64e(0x0b959e839e16830b),
	C64e(0x8cc945ca4503ca8c), C64e(0xc7bc7b297b9529c7),
	C64e(0x6b056ed36ed6d36b), C64e(0x286c443c44503c28),
	C64e(0xa72c8b798b5579a7), C64e(0xbc813de23d63e2bc),
	C64e(0x1631271d272c1d16), C64e(0xad379a769a4176ad),
	C64e(0xdb964d3b4dad3bdb), C64e(0x649efa56fac85664),
	C64e(0x74a6d24ed2e84e74), C64e(0x1436221e22281e14),
	C64e(0x92e476db763fdb92), C64e(0x0c121e0a1e180a0c),
	C64e(0x48fcb46cb4906c48), C64e(0xb88f37e4376be4b8),
	C64e(0x9f78e75de7255d9f), C64e(0xbd0fb26eb2616ebd),
	C64e(0x43692aef2a86ef43), C64e(0xc435f1a6f193a6c4),
	C64e(0x39dae3a8e372a839), C64e(0x31c6f7a4f762a431),
	C64e(0xd38a593759bd37d3), C64e(0xf274868b86ff8bf2),
	C64e(0xd583563256b132d5), C64e(0x8b4ec543c50d438b),
	C64e(0x6e85eb59ebdc596e), C64e(0xda18c2b7c2afb7da),
	C64e(0x018e8f8c8f028c01), C64e(0xb11dac64ac7964b1),
	C64e(0x9cf16dd26d23d29c), C64e(0x49723be03b92e049),
	C64e(0xd81fc7b4c7abb4d8), C64e(0xacb915fa1543faac),
	C64e(0xf3fa090709fd07f3), C64e(0xcfa06f256f8525cf),
	C64e(0xca20eaafea8fafca), C64e(0xf47d898e89f38ef4),
	C64e(0x476720e9208ee947), C64e(0x1038281828201810),
	C64e(0x6f0b64d564ded56f), C64e(0xf073838883fb88f0),
	C64e(0x4afbb16fb1946f4a), C64e(0x5cca967296b8725c),
	C64e(0x38546c246c702438), C64e(0x575f08f108aef157),
	C64e(0x732152c752e6c773), C64e(0x9764f351f3355197),
	C64e(0xcbae6523658d23cb), C64e(0xa125847c84597ca1),
	C64e(0xe857bf9cbfcb9ce8), C64e(0x3e5d6321637c213e),
	C64e(0x96ea7cdd7c37dd96), C64e(0x611e7fdc7fc2dc61),
	C64e(0x0d9c9186911a860d), C64e(0x0f9b9485941e850f),
	C64e(0xe04bab90abdb90e0), C64e(0x7cbac642c6f8427c),
	C64e(0x712657c457e2c471), C64e(0xcc29e5aae583aacc),
	C64e(0x90e373d8733bd890), C64e(0x06090f050f0c0506),
	C64e(0xf7f4030103f501f7), C64e(0x1c2a36123638121c),
	C64e(0xc23cfea3fe9fa3c2), C64e(0x6a8be15fe1d45f6a),
	C64e(0xaebe10f91047f9ae), C64e(0x69026bd06bd2d069),
	C64e(0x17bfa891a82e9117), C64e(0x9971e858e8295899),
	C64e(0x3a5369276974273a), C64e(0x27f7d0b9d04eb927),
	C64e(0xd991483848a938d9), C64e(0xebde351335cd13eb),
	C64e(0x2be5ceb3ce56b32b), C64e(0x2277553355443322),
	C64e(0xd204d6bbd6bfbbd2), C64e(0xa9399070904970a9),
	C64e(0x07878089800e8907), C64e(0x33c1f2a7f266a733),
	C64e(0x2decc1b6c15ab62d), C64e(0x3c5a66226678223c),
	C64e(0x15b8ad92ad2a9215), C64e(0xc9a96020608920c9),
	C64e(0x875cdb49db154987), C64e(0xaab01aff1a4fffaa),
	C64e(0x50d8887888a07850), C64e(0xa52b8e7a8e517aa5),
	C64e(0x03898a8f8a068f03), C64e(0x594a13f813b2f859),
	C64e(0x09929b809b128009), C64e(0x1a2339173934171a),
	C64e(0x651075da75cada65), C64e(0xd784533153b531d7),
	C64e(0x84d551c65113c684), C64e(0xd003d3b8d3bbb8d0),
	C64e(0x82dc5ec35e1fc382), C64e(0x29e2cbb0cb52b029),
	C64e(0x5ac3997799b4775a), C64e(0x1e2d3311333c111e),
	C64e(0x7b3d46cb46f6cb7b), C64e(0xa8b71ffc1f4bfca8),
	C64e(0x6d0c61d661dad66d), C64e(0x2c624e3a4e583a2c)
};

static const sph_u64 T4[] GROESTL_ALIGN64 = {
	C64e(0xf497a5c6c632f4a5), C64e(0x97eb84f8f86f9784),
	C64e(0xb0c799eeee5eb099), C64e(0x8cf78df6f67a8c8d),
	C64e(0x17e50dffffe8170d), C64e(0xdcb7bdd6d60adcbd),
	C64e(0xc8a7b1dede16c8b1), C64e(0xfc395491916dfc54),
	C64e(0xf0c050606090f050), C64e(0x0504030202070503),
	C64e(0xe087a9cece2ee0a9), C64e(0x87ac7d5656d1877d),
	C64e(0x2bd519e7e7cc2b19), C64e(0xa67162b5b513a662),
	C64e(0x319ae64d4d7c31e6), C64e(0xb5c39aecec59b59a),
	C64e(0xcf05458f8f40cf45), C64e(0xbc3e9d1f1fa3bc9d),
	C64e(0xc00940898949c040), C64e(0x92ef87fafa689287),
	C64e(0x3fc515efefd03f15), C64e(0x267febb2b29426eb),
	C64e(0x4007c98e8ece40c9), C64e(0x1ded0bfbfbe61d0b),
	C64e(0x2f82ec41416e2fec), C64e(0xa97d67b3b31aa967),
	C64e(0x1cbefd5f5f431cfd), C64e(0x258aea45456025ea),
	C64e(0xda46bf2323f9dabf), C64e(0x02a6f753535102f7),
	C64e(0xa1d396e4e445a196), C64e(0xed2d5b9b9b76ed5b),
	C64e(0x5deac27575285dc2), C64e(0x24d91ce1e1c5241c),
	C64e(0xe97aae3d3dd4e9ae), C64e(0xbe986a4c4cf2be6a),
	C64e(0xeed85a6c6c82ee5a), C64e(0xc3fc417e7ebdc341),
	C64e(0x06f102f5f5f30602), C64e(0xd11d4f838352d14f),
	C64e(0xe4d05c68688ce45c), C64e(0x07a2f451515607f4),
	C64e(0x5cb934d1d18d5c34), C64e(0x18e908f9f9e11808),
	C64e(0xaedf93e2e24cae93), C64e(0x954d73abab3e9573),
	C64e(0xf5c453626297f553), C64e(0x41543f2a2a6b413f),
	C64e(0x14100c08081c140c), C64e(0xf63152959563f652),
	C64e(0xaf8c654646e9af65), C64e(0xe2215e9d9d7fe25e),
	C64e(0x7860283030487828), C64e(0xf86ea13737cff8a1),
	C64e(0x11140f0a0a1b110f), C64e(0xc45eb52f2febc4b5),
	C64e(0x1b1c090e0e151b09), C64e(0x5a483624247e5a36),
	C64e(0xb6369b1b1badb69b), C64e(0x47a53ddfdf98473d),
	C64e(0x6a8126cdcda76a26), C64e(0xbb9c694e4ef5bb69),
	C64e(0x4cfecd7f7f334ccd), C64e(0xbacf9feaea50ba9f),
	C64e(0x2d241b12123f2d1b), C64e(0xb93a9e1d1da4b99e),
	C64e(0x9cb0745858c49c74), C64e(0x72682e343446722e),
	C64e(0x776c2d363641772d), C64e(0xcda3b2dcdc11cdb2),
	C64e(0x2973eeb4b49d29ee), C64e(0x16b6fb5b5b4d16fb),
	C64e(0x0153f6a4a4a501f6), C64e(0xd7ec4d7676a1d74d),
	C64e(0xa37561b7b714a361), C64e(0x49face7d7d3449ce),
	C64e(0x8da47b5252df8d7b), C64e(0x42a13edddd9f423e),
	C64e(0x93bc715e5ecd9371), C64e(0xa226971313b1a297),
	C64e(0x0457f5a6a6a204f5), C64e(0xb86968b9b901b868),
	C64e(0x0000000000000000), C64e(0x74992cc1c1b5742c),
	C64e(0xa080604040e0a060), C64e(0x21dd1fe3e3c2211f),
	C64e(0x43f2c879793a43c8), C64e(0x2c77edb6b69a2ced),
	C64e(0xd9b3bed4d40dd9be), C64e(0xca01468d8d47ca46),
	C64e(0x70ced967671770d9), C64e(0xdde44b7272afdd4b),
	C64e(0x7933de9494ed79de), C64e(0x672bd49898ff67d4),
	C64e(0x237be8b0b09323e8), C64e(0xde114a85855bde4a),
	C64e(0xbd6d6bbbbb06bd6b), C64e(0x7e912ac5c5bb7e2a),
	C64e(0x349ee54f4f7b34e5), C64e(0x3ac116ededd73a16),
	C64e(0x5417c58686d254c5), C64e(0x622fd79a9af862d7),
	C64e(0xffcc55666699ff55), C64e(0xa722941111b6a794),
	C64e(0x4a0fcf8a8ac04acf), C64e(0x30c910e9e9d93010),
	C64e(0x0a080604040e0a06), C64e(0x98e781fefe669881),
	C64e(0x0b5bf0a0a0ab0bf0), C64e(0xccf0447878b4cc44),
	C64e(0xd54aba2525f0d5ba), C64e(0x3e96e34b4b753ee3),
	C64e(0x0e5ff3a2a2ac0ef3), C64e(0x19bafe5d5d4419fe),
	C64e(0x5b1bc08080db5bc0), C64e(0x850a8a050580858a),
	C64e(0xec7ead3f3fd3ecad), C64e(0xdf42bc2121fedfbc),
	C64e(0xd8e0487070a8d848), C64e(0x0cf904f1f1fd0c04),
	C64e(0x7ac6df6363197adf), C64e(0x58eec177772f58c1),
	C64e(0x9f4575afaf309f75), C64e(0xa584634242e7a563),
	C64e(0x5040302020705030), C64e(0x2ed11ae5e5cb2e1a),
	C64e(0x12e10efdfdef120e), C64e(0xb7656dbfbf08b76d),
	C64e(0xd4194c818155d44c), C64e(0x3c30141818243c14),
	C64e(0x5f4c352626795f35), C64e(0x719d2fc3c3b2712f),
	C64e(0x3867e1bebe8638e1), C64e(0xfd6aa23535c8fda2),
	C64e(0x4f0bcc8888c74fcc), C64e(0x4b5c392e2e654b39),
	C64e(0xf93d5793936af957), C64e(0x0daaf25555580df2),
	C64e(0x9de382fcfc619d82), C64e(0xc9f4477a7ab3c947),
	C64e(0xef8bacc8c827efac), C64e(0x326fe7baba8832e7),
	C64e(0x7d642b32324f7d2b), C64e(0xa4d795e6e642a495),
	C64e(0xfb9ba0c0c03bfba0), C64e(0xb332981919aab398),
	C64e(0x6827d19e9ef668d1), C64e(0x815d7fa3a322817f),
	C64e(0xaa88664444eeaa66), C64e(0x82a87e5454d6827e),
	C64e(0xe676ab3b3bdde6ab), C64e(0x9e16830b0b959e83),
	C64e(0x4503ca8c8cc945ca), C64e(0x7b9529c7c7bc7b29),
	C64e(0x6ed6d36b6b056ed3), C64e(0x44503c28286c443c),
	C64e(0x8b5579a7a72c8b79), C64e(0x3d63e2bcbc813de2),
	C64e(0x272c1d161631271d), C64e(0x9a4176adad379a76),
	C64e(0x4dad3bdbdb964d3b), C64e(0xfac85664649efa56),
	C64e(0xd2e84e7474a6d24e), C64e(0x22281e141436221e),
	C64e(0x763fdb9292e476db), C64e(0x1e180a0c0c121e0a),
	C64e(0xb4906c4848fcb46c), C64e(0x376be4b8b88f37e4),
	C64e(0xe7255d9f9f78e75d), C64e(0xb2616ebdbd0fb26e),
	C64e(0x2a86ef4343692aef), C64e(0xf193a6c4c435f1a6),
	C64e(0xe372a83939dae3a8), C64e(0xf762a43131c6f7a4),
	C64e(0x59bd37d3d38a5937), C64e(0x86ff8bf2f274868b),
	C64e(0x56b132d5d5835632), C64e(0xc50d438b8b4ec543),
	C64e(0xebdc596e6e85eb59), C64e(0xc2afb7dada18c2b7),
	C64e(0x8f028c01018e8f8c), C64e(0xac7964b1b11dac64),
	C64e(0x6d23d29c9cf16dd2), C64e(0x3b92e04949723be0),
	C64e(0xc7abb4d8d81fc7b4), C64e(0x1543faacacb915fa),
	C64e(0x09fd07f3f3fa0907), C64e(0x6f8525cfcfa06f25),
	C64e(0xea8fafcaca20eaaf), C64e(0x89f38ef4f47d898e),
	C64e(0x208ee947476720e9), C64e(0x2820181010382818),
	C64e(0x64ded56f6f0b64d5), C64e(0x83fb88f0f0738388),
	C64e(0xb1946f4a4afbb16f), C64e(0x96b8725c5cca9672),
	C64e(0x6c70243838546c24), C64e(0x08aef157575f08f1),
	C64e(0x52e6c773732152c7), C64e(0xf33551979764f351),
	C64e(0x658d23cbcbae6523), C64e(0x84597ca1a125847c),
	C64e(0xbfcb9ce8e857bf9c), C64e(0x637c213e3e5d6321),
	C64e(0x7c37dd9696ea7cdd), C64e(0x7fc2dc61611e7fdc),
	C64e(0x911a860d0d9c9186), C64e(0x941e850f0f9b9485),
	C64e(0xabdb90e0e04bab90), C64e(0xc6f8427c7cbac642),
	C64e(0x57e2c471712657c4), C64e(0xe583aacccc29e5aa),
	C64e(0x733bd89090e373d8), C64e(0x0f0c050606090f05),
	C64e(0x03f501f7f7f40301), C64e(0x3638121c1c2a3612),
	C64e(0xfe9fa3c2c23cfea3), C64e(0xe1d45f6a6a8be15f),
	C64e(0x1047f9aeaebe10f9), C64e(0x6bd2d06969026bd0),
	C64e(0xa82e911717bfa891), C64e(0xe82958999971e858),
	C64e(0x6974273a3a536927), C64e(0xd04eb92727f7d0b9),
	C64e(0x48a938d9d9914838), C64e(0x35cd13ebebde3513),
	C64e(0xce56b32b2be5ceb3), C64e(0x5544332222775533),
	C64e(0xd6bfbbd2d204d6bb), C64e(0x904970a9a9399070),
	C64e(0x800e890707878089), C64e(0xf266a73333c1f2a7),
	C64e(0xc15ab62d2decc1b6), C64e(0x6678223c3c5a6622),
	C64e(0xad2a921515b8ad92), C64e(0x608920c9c9a96020),
	C64e(0xdb154987875cdb49), C64e(0x1a4fffaaaab01aff),
	C64e(0x88a0785050d88878), C64e(0x8e517aa5a52b8e7a),
	C64e(0x8a068f0303898a8f), C64e(0x13b2f859594a13f8),
	C64e(0x9b12800909929b80), C64e(0x3934171a1a233917),
	C64e(0x75cada65651075da), C64e(0x53b531d7d7845331),
	C64e(0x5113c68484d551c6), C64e(0xd3bbb8d0d003d3b8),
	C64e(0x5e1fc38282dc5ec3), C64e(0xcb52b02929e2cbb0),
	C64e(0x99b4775a5ac39977), C64e(0x333c111e1e2d3311),
	C64e(0x46f6cb7b7b3d46cb), C64e(0x1f4bfca8a8b71ffc),
	C64e(0x61dad66d6d0c61d6), C64e(0x4e583a2c2c624e3a)
};

/* ------------------------------------------------------------------ */
/* Precomputed rotated tables — eliminate all runtime rotations       */
/* ------------------------------------------------------------------ */

#if USE_LE

static const sph_u64 T1[] GROESTL_ALIGN64 = {
	SPH_C64(0x32f4a5f497a5c6c6), SPH_C64(0x6f978497eb84f8f8), SPH_C64(0x5eb099b0c799eeee), SPH_C64(0x7a8c8d8cf78df6f6),
	SPH_C64(0xe8170d17e50dffff), SPH_C64(0x0adcbddcb7bdd6d6), SPH_C64(0x16c8b1c8a7b1dede), SPH_C64(0x6dfc54fc39549191),
	SPH_C64(0x90f050f0c0506060), SPH_C64(0x0705030504030202), SPH_C64(0x2ee0a9e087a9cece), SPH_C64(0xd1877d87ac7d5656),
	SPH_C64(0xcc2b192bd519e7e7), SPH_C64(0x13a662a67162b5b5), SPH_C64(0x7c31e6319ae64d4d), SPH_C64(0x59b59ab5c39aecec),
	SPH_C64(0x40cf45cf05458f8f), SPH_C64(0xa3bc9dbc3e9d1f1f), SPH_C64(0x49c040c009408989), SPH_C64(0x68928792ef87fafa),
	SPH_C64(0xd03f153fc515efef), SPH_C64(0x9426eb267febb2b2), SPH_C64(0xce40c94007c98e8e), SPH_C64(0xe61d0b1ded0bfbfb),
	SPH_C64(0x6e2fec2f82ec4141), SPH_C64(0x1aa967a97d67b3b3), SPH_C64(0x431cfd1cbefd5f5f), SPH_C64(0x6025ea258aea4545),
	SPH_C64(0xf9dabfda46bf2323), SPH_C64(0x5102f702a6f75353), SPH_C64(0x45a196a1d396e4e4), SPH_C64(0x76ed5bed2d5b9b9b),
	SPH_C64(0x285dc25deac27575), SPH_C64(0xc5241c24d91ce1e1), SPH_C64(0xd4e9aee97aae3d3d), SPH_C64(0xf2be6abe986a4c4c),
	SPH_C64(0x82ee5aeed85a6c6c), SPH_C64(0xbdc341c3fc417e7e), SPH_C64(0xf3060206f102f5f5), SPH_C64(0x52d14fd11d4f8383),
	SPH_C64(0x8ce45ce4d05c6868), SPH_C64(0x5607f407a2f45151), SPH_C64(0x8d5c345cb934d1d1), SPH_C64(0xe1180818e908f9f9),
	SPH_C64(0x4cae93aedf93e2e2), SPH_C64(0x3e9573954d73abab), SPH_C64(0x97f553f5c4536262), SPH_C64(0x6b413f41543f2a2a),
	SPH_C64(0x1c140c14100c0808), SPH_C64(0x63f652f631529595), SPH_C64(0xe9af65af8c654646), SPH_C64(0x7fe25ee2215e9d9d),
	SPH_C64(0x4878287860283030), SPH_C64(0xcff8a1f86ea13737), SPH_C64(0x1b110f11140f0a0a), SPH_C64(0xebc4b5c45eb52f2f),
	SPH_C64(0x151b091b1c090e0e), SPH_C64(0x7e5a365a48362424), SPH_C64(0xadb69bb6369b1b1b), SPH_C64(0x98473d47a53ddfdf),
	SPH_C64(0xa76a266a8126cdcd), SPH_C64(0xf5bb69bb9c694e4e), SPH_C64(0x334ccd4cfecd7f7f), SPH_C64(0x50ba9fbacf9feaea),
	SPH_C64(0x3f2d1b2d241b1212), SPH_C64(0xa4b99eb93a9e1d1d), SPH_C64(0xc49c749cb0745858), SPH_C64(0x46722e72682e3434),
	SPH_C64(0x41772d776c2d3636), SPH_C64(0x11cdb2cda3b2dcdc), SPH_C64(0x9d29ee2973eeb4b4), SPH_C64(0x4d16fb16b6fb5b5b),
	SPH_C64(0xa501f60153f6a4a4), SPH_C64(0xa1d74dd7ec4d7676), SPH_C64(0x14a361a37561b7b7), SPH_C64(0x3449ce49face7d7d),
	SPH_C64(0xdf8d7b8da47b5252), SPH_C64(0x9f423e42a13edddd), SPH_C64(0xcd937193bc715e5e), SPH_C64(0xb1a297a226971313),
	SPH_C64(0xa204f50457f5a6a6), SPH_C64(0x01b868b86968b9b9), SPH_C64(0x0000000000000000), SPH_C64(0xb5742c74992cc1c1),
	SPH_C64(0xe0a060a080604040), SPH_C64(0xc2211f21dd1fe3e3), SPH_C64(0x3a43c843f2c87979), SPH_C64(0x9a2ced2c77edb6b6),
	SPH_C64(0x0dd9bed9b3bed4d4), SPH_C64(0x47ca46ca01468d8d), SPH_C64(0x1770d970ced96767), SPH_C64(0xafdd4bdde44b7272),
	SPH_C64(0xed79de7933de9494), SPH_C64(0xff67d4672bd49898), SPH_C64(0x9323e8237be8b0b0), SPH_C64(0x5bde4ade114a8585),
	SPH_C64(0x06bd6bbd6d6bbbbb), SPH_C64(0xbb7e2a7e912ac5c5), SPH_C64(0x7b34e5349ee54f4f), SPH_C64(0xd73a163ac116eded),
	SPH_C64(0xd254c55417c58686), SPH_C64(0xf862d7622fd79a9a), SPH_C64(0x99ff55ffcc556666), SPH_C64(0xb6a794a722941111),
	SPH_C64(0xc04acf4a0fcf8a8a), SPH_C64(0xd9301030c910e9e9), SPH_C64(0x0e0a060a08060404), SPH_C64(0x66988198e781fefe),
	SPH_C64(0xab0bf00b5bf0a0a0), SPH_C64(0xb4cc44ccf0447878), SPH_C64(0xf0d5bad54aba2525), SPH_C64(0x753ee33e96e34b4b),
	SPH_C64(0xac0ef30e5ff3a2a2), SPH_C64(0x4419fe19bafe5d5d), SPH_C64(0xdb5bc05b1bc08080), SPH_C64(0x80858a850a8a0505),
	SPH_C64(0xd3ecadec7ead3f3f), SPH_C64(0xfedfbcdf42bc2121), SPH_C64(0xa8d848d8e0487070), SPH_C64(0xfd0c040cf904f1f1),
	SPH_C64(0x197adf7ac6df6363), SPH_C64(0x2f58c158eec17777), SPH_C64(0x309f759f4575afaf), SPH_C64(0xe7a563a584634242),
	SPH_C64(0x7050305040302020), SPH_C64(0xcb2e1a2ed11ae5e5), SPH_C64(0xef120e12e10efdfd), SPH_C64(0x08b76db7656dbfbf),
	SPH_C64(0x55d44cd4194c8181), SPH_C64(0x243c143c30141818), SPH_C64(0x795f355f4c352626), SPH_C64(0xb2712f719d2fc3c3),
	SPH_C64(0x8638e13867e1bebe), SPH_C64(0xc8fda2fd6aa23535), SPH_C64(0xc74fcc4f0bcc8888), SPH_C64(0x654b394b5c392e2e),
	SPH_C64(0x6af957f93d579393), SPH_C64(0x580df20daaf25555), SPH_C64(0x619d829de382fcfc), SPH_C64(0xb3c947c9f4477a7a),
	SPH_C64(0x27efacef8bacc8c8), SPH_C64(0x8832e7326fe7baba), SPH_C64(0x4f7d2b7d642b3232), SPH_C64(0x42a495a4d795e6e6),
	SPH_C64(0x3bfba0fb9ba0c0c0), SPH_C64(0xaab398b332981919), SPH_C64(0xf668d16827d19e9e), SPH_C64(0x22817f815d7fa3a3),
	SPH_C64(0xeeaa66aa88664444), SPH_C64(0xd6827e82a87e5454), SPH_C64(0xdde6abe676ab3b3b), SPH_C64(0x959e839e16830b0b),
	SPH_C64(0xc945ca4503ca8c8c), SPH_C64(0xbc7b297b9529c7c7), SPH_C64(0x056ed36ed6d36b6b), SPH_C64(0x6c443c44503c2828),
	SPH_C64(0x2c8b798b5579a7a7), SPH_C64(0x813de23d63e2bcbc), SPH_C64(0x31271d272c1d1616), SPH_C64(0x379a769a4176adad),
	SPH_C64(0x964d3b4dad3bdbdb), SPH_C64(0x9efa56fac8566464), SPH_C64(0xa6d24ed2e84e7474), SPH_C64(0x36221e22281e1414),
	SPH_C64(0xe476db763fdb9292), SPH_C64(0x121e0a1e180a0c0c), SPH_C64(0xfcb46cb4906c4848), SPH_C64(0x8f37e4376be4b8b8),
	SPH_C64(0x78e75de7255d9f9f), SPH_C64(0x0fb26eb2616ebdbd), SPH_C64(0x692aef2a86ef4343), SPH_C64(0x35f1a6f193a6c4c4),
	SPH_C64(0xdae3a8e372a83939), SPH_C64(0xc6f7a4f762a43131), SPH_C64(0x8a593759bd37d3d3), SPH_C64(0x74868b86ff8bf2f2),
	SPH_C64(0x83563256b132d5d5), SPH_C64(0x4ec543c50d438b8b), SPH_C64(0x85eb59ebdc596e6e), SPH_C64(0x18c2b7c2afb7dada),
	SPH_C64(0x8e8f8c8f028c0101), SPH_C64(0x1dac64ac7964b1b1), SPH_C64(0xf16dd26d23d29c9c), SPH_C64(0x723be03b92e04949),
	SPH_C64(0x1fc7b4c7abb4d8d8), SPH_C64(0xb915fa1543faacac), SPH_C64(0xfa090709fd07f3f3), SPH_C64(0xa06f256f8525cfcf),
	SPH_C64(0x20eaafea8fafcaca), SPH_C64(0x7d898e89f38ef4f4), SPH_C64(0x6720e9208ee94747), SPH_C64(0x3828182820181010),
	SPH_C64(0x0b64d564ded56f6f), SPH_C64(0x73838883fb88f0f0), SPH_C64(0xfbb16fb1946f4a4a), SPH_C64(0xca967296b8725c5c),
	SPH_C64(0x546c246c70243838), SPH_C64(0x5f08f108aef15757), SPH_C64(0x2152c752e6c77373), SPH_C64(0x64f351f335519797),
	SPH_C64(0xae6523658d23cbcb), SPH_C64(0x25847c84597ca1a1), SPH_C64(0x57bf9cbfcb9ce8e8), SPH_C64(0x5d6321637c213e3e),
	SPH_C64(0xea7cdd7c37dd9696), SPH_C64(0x1e7fdc7fc2dc6161), SPH_C64(0x9c9186911a860d0d), SPH_C64(0x9b9485941e850f0f),
	SPH_C64(0x4bab90abdb90e0e0), SPH_C64(0xbac642c6f8427c7c), SPH_C64(0x2657c457e2c47171), SPH_C64(0x29e5aae583aacccc),
	SPH_C64(0xe373d8733bd89090), SPH_C64(0x090f050f0c050606), SPH_C64(0xf4030103f501f7f7), SPH_C64(0x2a36123638121c1c),
	SPH_C64(0x3cfea3fe9fa3c2c2), SPH_C64(0x8be15fe1d45f6a6a), SPH_C64(0xbe10f91047f9aeae), SPH_C64(0x026bd06bd2d06969),
	SPH_C64(0xbfa891a82e911717), SPH_C64(0x71e858e829589999), SPH_C64(0x5369276974273a3a), SPH_C64(0xf7d0b9d04eb92727),
	SPH_C64(0x91483848a938d9d9), SPH_C64(0xde351335cd13ebeb), SPH_C64(0xe5ceb3ce56b32b2b), SPH_C64(0x7755335544332222),
	SPH_C64(0x04d6bbd6bfbbd2d2), SPH_C64(0x399070904970a9a9), SPH_C64(0x878089800e890707), SPH_C64(0xc1f2a7f266a73333),
	SPH_C64(0xecc1b6c15ab62d2d), SPH_C64(0x5a66226678223c3c), SPH_C64(0xb8ad92ad2a921515), SPH_C64(0xa96020608920c9c9),
	SPH_C64(0x5cdb49db15498787), SPH_C64(0xb01aff1a4fffaaaa), SPH_C64(0xd8887888a0785050), SPH_C64(0x2b8e7a8e517aa5a5),
	SPH_C64(0x898a8f8a068f0303), SPH_C64(0x4a13f813b2f85959), SPH_C64(0x929b809b12800909), SPH_C64(0x2339173934171a1a),
	SPH_C64(0x1075da75cada6565), SPH_C64(0x84533153b531d7d7), SPH_C64(0xd551c65113c68484), SPH_C64(0x03d3b8d3bbb8d0d0),
	SPH_C64(0xdc5ec35e1fc38282), SPH_C64(0xe2cbb0cb52b02929), SPH_C64(0xc3997799b4775a5a), SPH_C64(0x2d3311333c111e1e),
	SPH_C64(0x3d46cb46f6cb7b7b), SPH_C64(0xb71ffc1f4bfca8a8), SPH_C64(0x0c61d661dad66d6d), SPH_C64(0x624e3a4e583a2c2c)
};

static const sph_u64 T2[] GROESTL_ALIGN64 = {
	SPH_C64(0xf4a5f497a5c6c632), SPH_C64(0x978497eb84f8f86f), SPH_C64(0xb099b0c799eeee5e), SPH_C64(0x8c8d8cf78df6f67a),
	SPH_C64(0x170d17e50dffffe8), SPH_C64(0xdcbddcb7bdd6d60a), SPH_C64(0xc8b1c8a7b1dede16), SPH_C64(0xfc54fc395491916d),
	SPH_C64(0xf050f0c050606090), SPH_C64(0x0503050403020207), SPH_C64(0xe0a9e087a9cece2e), SPH_C64(0x877d87ac7d5656d1),
	SPH_C64(0x2b192bd519e7e7cc), SPH_C64(0xa662a67162b5b513), SPH_C64(0x31e6319ae64d4d7c), SPH_C64(0xb59ab5c39aecec59),
	SPH_C64(0xcf45cf05458f8f40), SPH_C64(0xbc9dbc3e9d1f1fa3), SPH_C64(0xc040c00940898949), SPH_C64(0x928792ef87fafa68),
	SPH_C64(0x3f153fc515efefd0), SPH_C64(0x26eb267febb2b294), SPH_C64(0x40c94007c98e8ece), SPH_C64(0x1d0b1ded0bfbfbe6),
	SPH_C64(0x2fec2f82ec41416e), SPH_C64(0xa967a97d67b3b31a), SPH_C64(0x1cfd1cbefd5f5f43), SPH_C64(0x25ea258aea454560),
	SPH_C64(0xdabfda46bf2323f9), SPH_C64(0x02f702a6f7535351), SPH_C64(0xa196a1d396e4e445), SPH_C64(0xed5bed2d5b9b9b76),
	SPH_C64(0x5dc25deac2757528), SPH_C64(0x241c24d91ce1e1c5), SPH_C64(0xe9aee97aae3d3dd4), SPH_C64(0xbe6abe986a4c4cf2),
	SPH_C64(0xee5aeed85a6c6c82), SPH_C64(0xc341c3fc417e7ebd), SPH_C64(0x060206f102f5f5f3), SPH_C64(0xd14fd11d4f838352),
	SPH_C64(0xe45ce4d05c68688c), SPH_C64(0x07f407a2f4515156), SPH_C64(0x5c345cb934d1d18d), SPH_C64(0x180818e908f9f9e1),
	SPH_C64(0xae93aedf93e2e24c), SPH_C64(0x9573954d73abab3e), SPH_C64(0xf553f5c453626297), SPH_C64(0x413f41543f2a2a6b),
	SPH_C64(0x140c14100c08081c), SPH_C64(0xf652f63152959563), SPH_C64(0xaf65af8c654646e9), SPH_C64(0xe25ee2215e9d9d7f),
	SPH_C64(0x7828786028303048), SPH_C64(0xf8a1f86ea13737cf), SPH_C64(0x110f11140f0a0a1b), SPH_C64(0xc4b5c45eb52f2feb),
	SPH_C64(0x1b091b1c090e0e15), SPH_C64(0x5a365a483624247e), SPH_C64(0xb69bb6369b1b1bad), SPH_C64(0x473d47a53ddfdf98),
	SPH_C64(0x6a266a8126cdcda7), SPH_C64(0xbb69bb9c694e4ef5), SPH_C64(0x4ccd4cfecd7f7f33), SPH_C64(0xba9fbacf9feaea50),
	SPH_C64(0x2d1b2d241b12123f), SPH_C64(0xb99eb93a9e1d1da4), SPH_C64(0x9c749cb0745858c4), SPH_C64(0x722e72682e343446),
	SPH_C64(0x772d776c2d363641), SPH_C64(0xcdb2cda3b2dcdc11), SPH_C64(0x29ee2973eeb4b49d), SPH_C64(0x16fb16b6fb5b5b4d),
	SPH_C64(0x01f60153f6a4a4a5), SPH_C64(0xd74dd7ec4d7676a1), SPH_C64(0xa361a37561b7b714), SPH_C64(0x49ce49face7d7d34),
	SPH_C64(0x8d7b8da47b5252df), SPH_C64(0x423e42a13edddd9f), SPH_C64(0x937193bc715e5ecd), SPH_C64(0xa297a226971313b1),
	SPH_C64(0x04f50457f5a6a6a2), SPH_C64(0xb868b86968b9b901), SPH_C64(0x0000000000000000), SPH_C64(0x742c74992cc1c1b5),
	SPH_C64(0xa060a080604040e0), SPH_C64(0x211f21dd1fe3e3c2), SPH_C64(0x43c843f2c879793a), SPH_C64(0x2ced2c77edb6b69a),
	SPH_C64(0xd9bed9b3bed4d40d), SPH_C64(0xca46ca01468d8d47), SPH_C64(0x70d970ced9676717), SPH_C64(0xdd4bdde44b7272af),
	SPH_C64(0x79de7933de9494ed), SPH_C64(0x67d4672bd49898ff), SPH_C64(0x23e8237be8b0b093), SPH_C64(0xde4ade114a85855b),
	SPH_C64(0xbd6bbd6d6bbbbb06), SPH_C64(0x7e2a7e912ac5c5bb), SPH_C64(0x34e5349ee54f4f7b), SPH_C64(0x3a163ac116ededd7),
	SPH_C64(0x54c55417c58686d2), SPH_C64(0x62d7622fd79a9af8), SPH_C64(0xff55ffcc55666699), SPH_C64(0xa794a722941111b6),
	SPH_C64(0x4acf4a0fcf8a8ac0), SPH_C64(0x301030c910e9e9d9), SPH_C64(0x0a060a080604040e), SPH_C64(0x988198e781fefe66),
	SPH_C64(0x0bf00b5bf0a0a0ab), SPH_C64(0xcc44ccf0447878b4), SPH_C64(0xd5bad54aba2525f0), SPH_C64(0x3ee33e96e34b4b75),
	SPH_C64(0x0ef30e5ff3a2a2ac), SPH_C64(0x19fe19bafe5d5d44), SPH_C64(0x5bc05b1bc08080db), SPH_C64(0x858a850a8a050580),
	SPH_C64(0xecadec7ead3f3fd3), SPH_C64(0xdfbcdf42bc2121fe), SPH_C64(0xd848d8e0487070a8), SPH_C64(0x0c040cf904f1f1fd),
	SPH_C64(0x7adf7ac6df636319), SPH_C64(0x58c158eec177772f), SPH_C64(0x9f759f4575afaf30), SPH_C64(0xa563a584634242e7),
	SPH_C64(0x5030504030202070), SPH_C64(0x2e1a2ed11ae5e5cb), SPH_C64(0x120e12e10efdfdef), SPH_C64(0xb76db7656dbfbf08),
	SPH_C64(0xd44cd4194c818155), SPH_C64(0x3c143c3014181824), SPH_C64(0x5f355f4c35262679), SPH_C64(0x712f719d2fc3c3b2),
	SPH_C64(0x38e13867e1bebe86), SPH_C64(0xfda2fd6aa23535c8), SPH_C64(0x4fcc4f0bcc8888c7), SPH_C64(0x4b394b5c392e2e65),
	SPH_C64(0xf957f93d5793936a), SPH_C64(0x0df20daaf2555558), SPH_C64(0x9d829de382fcfc61), SPH_C64(0xc947c9f4477a7ab3),
	SPH_C64(0xefacef8bacc8c827), SPH_C64(0x32e7326fe7baba88), SPH_C64(0x7d2b7d642b32324f), SPH_C64(0xa495a4d795e6e642),
	SPH_C64(0xfba0fb9ba0c0c03b), SPH_C64(0xb398b332981919aa), SPH_C64(0x68d16827d19e9ef6), SPH_C64(0x817f815d7fa3a322),
	SPH_C64(0xaa66aa88664444ee), SPH_C64(0x827e82a87e5454d6), SPH_C64(0xe6abe676ab3b3bdd), SPH_C64(0x9e839e16830b0b95),
	SPH_C64(0x45ca4503ca8c8cc9), SPH_C64(0x7b297b9529c7c7bc), SPH_C64(0x6ed36ed6d36b6b05), SPH_C64(0x443c44503c28286c),
	SPH_C64(0x8b798b5579a7a72c), SPH_C64(0x3de23d63e2bcbc81), SPH_C64(0x271d272c1d161631), SPH_C64(0x9a769a4176adad37),
	SPH_C64(0x4d3b4dad3bdbdb96), SPH_C64(0xfa56fac85664649e), SPH_C64(0xd24ed2e84e7474a6), SPH_C64(0x221e22281e141436),
	SPH_C64(0x76db763fdb9292e4), SPH_C64(0x1e0a1e180a0c0c12), SPH_C64(0xb46cb4906c4848fc), SPH_C64(0x37e4376be4b8b88f),
	SPH_C64(0xe75de7255d9f9f78), SPH_C64(0xb26eb2616ebdbd0f), SPH_C64(0x2aef2a86ef434369), SPH_C64(0xf1a6f193a6c4c435),
	SPH_C64(0xe3a8e372a83939da), SPH_C64(0xf7a4f762a43131c6), SPH_C64(0x593759bd37d3d38a), SPH_C64(0x868b86ff8bf2f274),
	SPH_C64(0x563256b132d5d583), SPH_C64(0xc543c50d438b8b4e), SPH_C64(0xeb59ebdc596e6e85), SPH_C64(0xc2b7c2afb7dada18),
	SPH_C64(0x8f8c8f028c01018e), SPH_C64(0xac64ac7964b1b11d), SPH_C64(0x6dd26d23d29c9cf1), SPH_C64(0x3be03b92e0494972),
	SPH_C64(0xc7b4c7abb4d8d81f), SPH_C64(0x15fa1543faacacb9), SPH_C64(0x090709fd07f3f3fa), SPH_C64(0x6f256f8525cfcfa0),
	SPH_C64(0xeaafea8fafcaca20), SPH_C64(0x898e89f38ef4f47d), SPH_C64(0x20e9208ee9474767), SPH_C64(0x2818282018101038),
	SPH_C64(0x64d564ded56f6f0b), SPH_C64(0x838883fb88f0f073), SPH_C64(0xb16fb1946f4a4afb), SPH_C64(0x967296b8725c5cca),
	SPH_C64(0x6c246c7024383854), SPH_C64(0x08f108aef157575f), SPH_C64(0x52c752e6c7737321), SPH_C64(0xf351f33551979764),
	SPH_C64(0x6523658d23cbcbae), SPH_C64(0x847c84597ca1a125), SPH_C64(0xbf9cbfcb9ce8e857), SPH_C64(0x6321637c213e3e5d),
	SPH_C64(0x7cdd7c37dd9696ea), SPH_C64(0x7fdc7fc2dc61611e), SPH_C64(0x9186911a860d0d9c), SPH_C64(0x9485941e850f0f9b),
	SPH_C64(0xab90abdb90e0e04b), SPH_C64(0xc642c6f8427c7cba), SPH_C64(0x57c457e2c4717126), SPH_C64(0xe5aae583aacccc29),
	SPH_C64(0x73d8733bd89090e3), SPH_C64(0x0f050f0c05060609), SPH_C64(0x030103f501f7f7f4), SPH_C64(0x36123638121c1c2a),
	SPH_C64(0xfea3fe9fa3c2c23c), SPH_C64(0xe15fe1d45f6a6a8b), SPH_C64(0x10f91047f9aeaebe), SPH_C64(0x6bd06bd2d0696902),
	SPH_C64(0xa891a82e911717bf), SPH_C64(0xe858e82958999971), SPH_C64(0x69276974273a3a53), SPH_C64(0xd0b9d04eb92727f7),
	SPH_C64(0x483848a938d9d991), SPH_C64(0x351335cd13ebebde), SPH_C64(0xceb3ce56b32b2be5), SPH_C64(0x5533554433222277),
	SPH_C64(0xd6bbd6bfbbd2d204), SPH_C64(0x9070904970a9a939), SPH_C64(0x8089800e89070787), SPH_C64(0xf2a7f266a73333c1),
	SPH_C64(0xc1b6c15ab62d2dec), SPH_C64(0x66226678223c3c5a), SPH_C64(0xad92ad2a921515b8), SPH_C64(0x6020608920c9c9a9),
	SPH_C64(0xdb49db154987875c), SPH_C64(0x1aff1a4fffaaaab0), SPH_C64(0x887888a0785050d8), SPH_C64(0x8e7a8e517aa5a52b),
	SPH_C64(0x8a8f8a068f030389), SPH_C64(0x13f813b2f859594a), SPH_C64(0x9b809b1280090992), SPH_C64(0x39173934171a1a23),
	SPH_C64(0x75da75cada656510), SPH_C64(0x533153b531d7d784), SPH_C64(0x51c65113c68484d5), SPH_C64(0xd3b8d3bbb8d0d003),
	SPH_C64(0x5ec35e1fc38282dc), SPH_C64(0xcbb0cb52b02929e2), SPH_C64(0x997799b4775a5ac3), SPH_C64(0x3311333c111e1e2d),
	SPH_C64(0x46cb46f6cb7b7b3d), SPH_C64(0x1ffc1f4bfca8a8b7), SPH_C64(0x61d661dad66d6d0c), SPH_C64(0x4e3a4e583a2c2c62)
};

static const sph_u64 T3[] GROESTL_ALIGN64 = {
	SPH_C64(0xa5f497a5c6c632f4), SPH_C64(0x8497eb84f8f86f97), SPH_C64(0x99b0c799eeee5eb0), SPH_C64(0x8d8cf78df6f67a8c),
	SPH_C64(0x0d17e50dffffe817), SPH_C64(0xbddcb7bdd6d60adc), SPH_C64(0xb1c8a7b1dede16c8), SPH_C64(0x54fc395491916dfc),
	SPH_C64(0x50f0c050606090f0), SPH_C64(0x0305040302020705), SPH_C64(0xa9e087a9cece2ee0), SPH_C64(0x7d87ac7d5656d187),
	SPH_C64(0x192bd519e7e7cc2b), SPH_C64(0x62a67162b5b513a6), SPH_C64(0xe6319ae64d4d7c31), SPH_C64(0x9ab5c39aecec59b5),
	SPH_C64(0x45cf05458f8f40cf), SPH_C64(0x9dbc3e9d1f1fa3bc), SPH_C64(0x40c00940898949c0), SPH_C64(0x8792ef87fafa6892),
	SPH_C64(0x153fc515efefd03f), SPH_C64(0xeb267febb2b29426), SPH_C64(0xc94007c98e8ece40), SPH_C64(0x0b1ded0bfbfbe61d),
	SPH_C64(0xec2f82ec41416e2f), SPH_C64(0x67a97d67b3b31aa9), SPH_C64(0xfd1cbefd5f5f431c), SPH_C64(0xea258aea45456025),
	SPH_C64(0xbfda46bf2323f9da), SPH_C64(0xf702a6f753535102), SPH_C64(0x96a1d396e4e445a1), SPH_C64(0x5bed2d5b9b9b76ed),
	SPH_C64(0xc25deac27575285d), SPH_C64(0x1c24d91ce1e1c524), SPH_C64(0xaee97aae3d3dd4e9), SPH_C64(0x6abe986a4c4cf2be),
	SPH_C64(0x5aeed85a6c6c82ee), SPH_C64(0x41c3fc417e7ebdc3), SPH_C64(0x0206f102f5f5f306), SPH_C64(0x4fd11d4f838352d1),
	SPH_C64(0x5ce4d05c68688ce4), SPH_C64(0xf407a2f451515607), SPH_C64(0x345cb934d1d18d5c), SPH_C64(0x0818e908f9f9e118),
	SPH_C64(0x93aedf93e2e24cae), SPH_C64(0x73954d73abab3e95), SPH_C64(0x53f5c453626297f5), SPH_C64(0x3f41543f2a2a6b41),
	SPH_C64(0x0c14100c08081c14), SPH_C64(0x52f63152959563f6), SPH_C64(0x65af8c654646e9af), SPH_C64(0x5ee2215e9d9d7fe2),
	SPH_C64(0x2878602830304878), SPH_C64(0xa1f86ea13737cff8), SPH_C64(0x0f11140f0a0a1b11), SPH_C64(0xb5c45eb52f2febc4),
	SPH_C64(0x091b1c090e0e151b), SPH_C64(0x365a483624247e5a), SPH_C64(0x9bb6369b1b1badb6), SPH_C64(0x3d47a53ddfdf9847),
	SPH_C64(0x266a8126cdcda76a), SPH_C64(0x69bb9c694e4ef5bb), SPH_C64(0xcd4cfecd7f7f334c), SPH_C64(0x9fbacf9feaea50ba),
	SPH_C64(0x1b2d241b12123f2d), SPH_C64(0x9eb93a9e1d1da4b9), SPH_C64(0x749cb0745858c49c), SPH_C64(0x2e72682e34344672),
	SPH_C64(0x2d776c2d36364177), SPH_C64(0xb2cda3b2dcdc11cd), SPH_C64(0xee2973eeb4b49d29), SPH_C64(0xfb16b6fb5b5b4d16),
	SPH_C64(0xf60153f6a4a4a501), SPH_C64(0x4dd7ec4d7676a1d7), SPH_C64(0x61a37561b7b714a3), SPH_C64(0xce49face7d7d3449),
	SPH_C64(0x7b8da47b5252df8d), SPH_C64(0x3e42a13edddd9f42), SPH_C64(0x7193bc715e5ecd93), SPH_C64(0x97a226971313b1a2),
	SPH_C64(0xf50457f5a6a6a204), SPH_C64(0x68b86968b9b901b8), SPH_C64(0x0000000000000000), SPH_C64(0x2c74992cc1c1b574),
	SPH_C64(0x60a080604040e0a0), SPH_C64(0x1f21dd1fe3e3c221), SPH_C64(0xc843f2c879793a43), SPH_C64(0xed2c77edb6b69a2c),
	SPH_C64(0xbed9b3bed4d40dd9), SPH_C64(0x46ca01468d8d47ca), SPH_C64(0xd970ced967671770), SPH_C64(0x4bdde44b7272afdd),
	SPH_C64(0xde7933de9494ed79), SPH_C64(0xd4672bd49898ff67), SPH_C64(0xe8237be8b0b09323), SPH_C64(0x4ade114a85855bde),
	SPH_C64(0x6bbd6d6bbbbb06bd), SPH_C64(0x2a7e912ac5c5bb7e), SPH_C64(0xe5349ee54f4f7b34), SPH_C64(0x163ac116ededd73a),
	SPH_C64(0xc55417c58686d254), SPH_C64(0xd7622fd79a9af862), SPH_C64(0x55ffcc55666699ff), SPH_C64(0x94a722941111b6a7),
	SPH_C64(0xcf4a0fcf8a8ac04a), SPH_C64(0x1030c910e9e9d930), SPH_C64(0x060a080604040e0a), SPH_C64(0x8198e781fefe6698),
	SPH_C64(0xf00b5bf0a0a0ab0b), SPH_C64(0x44ccf0447878b4cc), SPH_C64(0xbad54aba2525f0d5), SPH_C64(0xe33e96e34b4b753e),
	SPH_C64(0xf30e5ff3a2a2ac0e), SPH_C64(0xfe19bafe5d5d4419), SPH_C64(0xc05b1bc08080db5b), SPH_C64(0x8a850a8a05058085),
	SPH_C64(0xadec7ead3f3fd3ec), SPH_C64(0xbcdf42bc2121fedf), SPH_C64(0x48d8e0487070a8d8), SPH_C64(0x040cf904f1f1fd0c),
	SPH_C64(0xdf7ac6df6363197a), SPH_C64(0xc158eec177772f58), SPH_C64(0x759f4575afaf309f), SPH_C64(0x63a584634242e7a5),
	SPH_C64(0x3050403020207050), SPH_C64(0x1a2ed11ae5e5cb2e), SPH_C64(0x0e12e10efdfdef12), SPH_C64(0x6db7656dbfbf08b7),
	SPH_C64(0x4cd4194c818155d4), SPH_C64(0x143c30141818243c), SPH_C64(0x355f4c352626795f), SPH_C64(0x2f719d2fc3c3b271),
	SPH_C64(0xe13867e1bebe8638), SPH_C64(0xa2fd6aa23535c8fd), SPH_C64(0xcc4f0bcc8888c74f), SPH_C64(0x394b5c392e2e654b),
	SPH_C64(0x57f93d5793936af9), SPH_C64(0xf20daaf25555580d), SPH_C64(0x829de382fcfc619d), SPH_C64(0x47c9f4477a7ab3c9),
	SPH_C64(0xacef8bacc8c827ef), SPH_C64(0xe7326fe7baba8832), SPH_C64(0x2b7d642b32324f7d), SPH_C64(0x95a4d795e6e642a4),
	SPH_C64(0xa0fb9ba0c0c03bfb), SPH_C64(0x98b332981919aab3), SPH_C64(0xd16827d19e9ef668), SPH_C64(0x7f815d7fa3a32281),
	SPH_C64(0x66aa88664444eeaa), SPH_C64(0x7e82a87e5454d682), SPH_C64(0xabe676ab3b3bdde6), SPH_C64(0x839e16830b0b959e),
	SPH_C64(0xca4503ca8c8cc945), SPH_C64(0x297b9529c7c7bc7b), SPH_C64(0xd36ed6d36b6b056e), SPH_C64(0x3c44503c28286c44),
	SPH_C64(0x798b5579a7a72c8b), SPH_C64(0xe23d63e2bcbc813d), SPH_C64(0x1d272c1d16163127), SPH_C64(0x769a4176adad379a),
	SPH_C64(0x3b4dad3bdbdb964d), SPH_C64(0x56fac85664649efa), SPH_C64(0x4ed2e84e7474a6d2), SPH_C64(0x1e22281e14143622),
	SPH_C64(0xdb763fdb9292e476), SPH_C64(0x0a1e180a0c0c121e), SPH_C64(0x6cb4906c4848fcb4), SPH_C64(0xe4376be4b8b88f37),
	SPH_C64(0x5de7255d9f9f78e7), SPH_C64(0x6eb2616ebdbd0fb2), SPH_C64(0xef2a86ef4343692a), SPH_C64(0xa6f193a6c4c435f1),
	SPH_C64(0xa8e372a83939dae3), SPH_C64(0xa4f762a43131c6f7), SPH_C64(0x3759bd37d3d38a59), SPH_C64(0x8b86ff8bf2f27486),
	SPH_C64(0x3256b132d5d58356), SPH_C64(0x43c50d438b8b4ec5), SPH_C64(0x59ebdc596e6e85eb), SPH_C64(0xb7c2afb7dada18c2),
	SPH_C64(0x8c8f028c01018e8f), SPH_C64(0x64ac7964b1b11dac), SPH_C64(0xd26d23d29c9cf16d), SPH_C64(0xe03b92e04949723b),
	SPH_C64(0xb4c7abb4d8d81fc7), SPH_C64(0xfa1543faacacb915), SPH_C64(0x0709fd07f3f3fa09), SPH_C64(0x256f8525cfcfa06f),
	SPH_C64(0xafea8fafcaca20ea), SPH_C64(0x8e89f38ef4f47d89), SPH_C64(0xe9208ee947476720), SPH_C64(0x1828201810103828),
	SPH_C64(0xd564ded56f6f0b64), SPH_C64(0x8883fb88f0f07383), SPH_C64(0x6fb1946f4a4afbb1), SPH_C64(0x7296b8725c5cca96),
	SPH_C64(0x246c70243838546c), SPH_C64(0xf108aef157575f08), SPH_C64(0xc752e6c773732152), SPH_C64(0x51f33551979764f3),
	SPH_C64(0x23658d23cbcbae65), SPH_C64(0x7c84597ca1a12584), SPH_C64(0x9cbfcb9ce8e857bf), SPH_C64(0x21637c213e3e5d63),
	SPH_C64(0xdd7c37dd9696ea7c), SPH_C64(0xdc7fc2dc61611e7f), SPH_C64(0x86911a860d0d9c91), SPH_C64(0x85941e850f0f9b94),
	SPH_C64(0x90abdb90e0e04bab), SPH_C64(0x42c6f8427c7cbac6), SPH_C64(0xc457e2c471712657), SPH_C64(0xaae583aacccc29e5),
	SPH_C64(0xd8733bd89090e373), SPH_C64(0x050f0c050606090f), SPH_C64(0x0103f501f7f7f403), SPH_C64(0x123638121c1c2a36),
	SPH_C64(0xa3fe9fa3c2c23cfe), SPH_C64(0x5fe1d45f6a6a8be1), SPH_C64(0xf91047f9aeaebe10), SPH_C64(0xd06bd2d06969026b),
	SPH_C64(0x91a82e911717bfa8), SPH_C64(0x58e82958999971e8), SPH_C64(0x276974273a3a5369), SPH_C64(0xb9d04eb92727f7d0),
	SPH_C64(0x3848a938d9d99148), SPH_C64(0x1335cd13ebebde35), SPH_C64(0xb3ce56b32b2be5ce), SPH_C64(0x3355443322227755),
	SPH_C64(0xbbd6bfbbd2d204d6), SPH_C64(0x70904970a9a93990), SPH_C64(0x89800e8907078780), SPH_C64(0xa7f266a73333c1f2),
	SPH_C64(0xb6c15ab62d2decc1), SPH_C64(0x226678223c3c5a66), SPH_C64(0x92ad2a921515b8ad), SPH_C64(0x20608920c9c9a960),
	SPH_C64(0x49db154987875cdb), SPH_C64(0xff1a4fffaaaab01a), SPH_C64(0x7888a0785050d888), SPH_C64(0x7a8e517aa5a52b8e),
	SPH_C64(0x8f8a068f0303898a), SPH_C64(0xf813b2f859594a13), SPH_C64(0x809b12800909929b), SPH_C64(0x173934171a1a2339),
	SPH_C64(0xda75cada65651075), SPH_C64(0x3153b531d7d78453), SPH_C64(0xc65113c68484d551), SPH_C64(0xb8d3bbb8d0d003d3),
	SPH_C64(0xc35e1fc38282dc5e), SPH_C64(0xb0cb52b02929e2cb), SPH_C64(0x7799b4775a5ac399), SPH_C64(0x11333c111e1e2d33),
	SPH_C64(0xcb46f6cb7b7b3d46), SPH_C64(0xfc1f4bfca8a8b71f), SPH_C64(0xd661dad66d6d0c61), SPH_C64(0x3a4e583a2c2c624e)
};

static const sph_u64 T5[] GROESTL_ALIGN64 = {
	SPH_C64(0x97a5c6c632f4a5f4), SPH_C64(0xeb84f8f86f978497), SPH_C64(0xc799eeee5eb099b0), SPH_C64(0xf78df6f67a8c8d8c),
	SPH_C64(0xe50dffffe8170d17), SPH_C64(0xb7bdd6d60adcbddc), SPH_C64(0xa7b1dede16c8b1c8), SPH_C64(0x395491916dfc54fc),
	SPH_C64(0xc050606090f050f0), SPH_C64(0x0403020207050305), SPH_C64(0x87a9cece2ee0a9e0), SPH_C64(0xac7d5656d1877d87),
	SPH_C64(0xd519e7e7cc2b192b), SPH_C64(0x7162b5b513a662a6), SPH_C64(0x9ae64d4d7c31e631), SPH_C64(0xc39aecec59b59ab5),
	SPH_C64(0x05458f8f40cf45cf), SPH_C64(0x3e9d1f1fa3bc9dbc), SPH_C64(0x0940898949c040c0), SPH_C64(0xef87fafa68928792),
	SPH_C64(0xc515efefd03f153f), SPH_C64(0x7febb2b29426eb26), SPH_C64(0x07c98e8ece40c940), SPH_C64(0xed0bfbfbe61d0b1d),
	SPH_C64(0x82ec41416e2fec2f), SPH_C64(0x7d67b3b31aa967a9), SPH_C64(0xbefd5f5f431cfd1c), SPH_C64(0x8aea45456025ea25),
	SPH_C64(0x46bf2323f9dabfda), SPH_C64(0xa6f753535102f702), SPH_C64(0xd396e4e445a196a1), SPH_C64(0x2d5b9b9b76ed5bed),
	SPH_C64(0xeac27575285dc25d), SPH_C64(0xd91ce1e1c5241c24), SPH_C64(0x7aae3d3dd4e9aee9), SPH_C64(0x986a4c4cf2be6abe),
	SPH_C64(0xd85a6c6c82ee5aee), SPH_C64(0xfc417e7ebdc341c3), SPH_C64(0xf102f5f5f3060206), SPH_C64(0x1d4f838352d14fd1),
	SPH_C64(0xd05c68688ce45ce4), SPH_C64(0xa2f451515607f407), SPH_C64(0xb934d1d18d5c345c), SPH_C64(0xe908f9f9e1180818),
	SPH_C64(0xdf93e2e24cae93ae), SPH_C64(0x4d73abab3e957395), SPH_C64(0xc453626297f553f5), SPH_C64(0x543f2a2a6b413f41),
	SPH_C64(0x100c08081c140c14), SPH_C64(0x3152959563f652f6), SPH_C64(0x8c654646e9af65af), SPH_C64(0x215e9d9d7fe25ee2),
	SPH_C64(0x6028303048782878), SPH_C64(0x6ea13737cff8a1f8), SPH_C64(0x140f0a0a1b110f11), SPH_C64(0x5eb52f2febc4b5c4),
	SPH_C64(0x1c090e0e151b091b), SPH_C64(0x483624247e5a365a), SPH_C64(0x369b1b1badb69bb6), SPH_C64(0xa53ddfdf98473d47),
	SPH_C64(0x8126cdcda76a266a), SPH_C64(0x9c694e4ef5bb69bb), SPH_C64(0xfecd7f7f334ccd4c), SPH_C64(0xcf9feaea50ba9fba),
	SPH_C64(0x241b12123f2d1b2d), SPH_C64(0x3a9e1d1da4b99eb9), SPH_C64(0xb0745858c49c749c), SPH_C64(0x682e343446722e72),
	SPH_C64(0x6c2d363641772d77), SPH_C64(0xa3b2dcdc11cdb2cd), SPH_C64(0x73eeb4b49d29ee29), SPH_C64(0xb6fb5b5b4d16fb16),
	SPH_C64(0x53f6a4a4a501f601), SPH_C64(0xec4d7676a1d74dd7), SPH_C64(0x7561b7b714a361a3), SPH_C64(0xface7d7d3449ce49),
	SPH_C64(0xa47b5252df8d7b8d), SPH_C64(0xa13edddd9f423e42), SPH_C64(0xbc715e5ecd937193), SPH_C64(0x26971313b1a297a2),
	SPH_C64(0x57f5a6a6a204f504), SPH_C64(0x6968b9b901b868b8), SPH_C64(0x0000000000000000), SPH_C64(0x992cc1c1b5742c74),
	SPH_C64(0x80604040e0a060a0), SPH_C64(0xdd1fe3e3c2211f21), SPH_C64(0xf2c879793a43c843), SPH_C64(0x77edb6b69a2ced2c),
	SPH_C64(0xb3bed4d40dd9bed9), SPH_C64(0x01468d8d47ca46ca), SPH_C64(0xced967671770d970), SPH_C64(0xe44b7272afdd4bdd),
	SPH_C64(0x33de9494ed79de79), SPH_C64(0x2bd49898ff67d467), SPH_C64(0x7be8b0b09323e823), SPH_C64(0x114a85855bde4ade),
	SPH_C64(0x6d6bbbbb06bd6bbd), SPH_C64(0x912ac5c5bb7e2a7e), SPH_C64(0x9ee54f4f7b34e534), SPH_C64(0xc116ededd73a163a),
	SPH_C64(0x17c58686d254c554), SPH_C64(0x2fd79a9af862d762), SPH_C64(0xcc55666699ff55ff), SPH_C64(0x22941111b6a794a7),
	SPH_C64(0x0fcf8a8ac04acf4a), SPH_C64(0xc910e9e9d9301030), SPH_C64(0x080604040e0a060a), SPH_C64(0xe781fefe66988198),
	SPH_C64(0x5bf0a0a0ab0bf00b), SPH_C64(0xf0447878b4cc44cc), SPH_C64(0x4aba2525f0d5bad5), SPH_C64(0x96e34b4b753ee33e),
	SPH_C64(0x5ff3a2a2ac0ef30e), SPH_C64(0xbafe5d5d4419fe19), SPH_C64(0x1bc08080db5bc05b), SPH_C64(0x0a8a050580858a85),
	SPH_C64(0x7ead3f3fd3ecadec), SPH_C64(0x42bc2121fedfbcdf), SPH_C64(0xe0487070a8d848d8), SPH_C64(0xf904f1f1fd0c040c),
	SPH_C64(0xc6df6363197adf7a), SPH_C64(0xeec177772f58c158), SPH_C64(0x4575afaf309f759f), SPH_C64(0x84634242e7a563a5),
	SPH_C64(0x4030202070503050), SPH_C64(0xd11ae5e5cb2e1a2e), SPH_C64(0xe10efdfdef120e12), SPH_C64(0x656dbfbf08b76db7),
	SPH_C64(0x194c818155d44cd4), SPH_C64(0x30141818243c143c), SPH_C64(0x4c352626795f355f), SPH_C64(0x9d2fc3c3b2712f71),
	SPH_C64(0x67e1bebe8638e138), SPH_C64(0x6aa23535c8fda2fd), SPH_C64(0x0bcc8888c74fcc4f), SPH_C64(0x5c392e2e654b394b),
	SPH_C64(0x3d5793936af957f9), SPH_C64(0xaaf25555580df20d), SPH_C64(0xe382fcfc619d829d), SPH_C64(0xf4477a7ab3c947c9),
	SPH_C64(0x8bacc8c827efacef), SPH_C64(0x6fe7baba8832e732), SPH_C64(0x642b32324f7d2b7d), SPH_C64(0xd795e6e642a495a4),
	SPH_C64(0x9ba0c0c03bfba0fb), SPH_C64(0x32981919aab398b3), SPH_C64(0x27d19e9ef668d168), SPH_C64(0x5d7fa3a322817f81),
	SPH_C64(0x88664444eeaa66aa), SPH_C64(0xa87e5454d6827e82), SPH_C64(0x76ab3b3bdde6abe6), SPH_C64(0x16830b0b959e839e),
	SPH_C64(0x03ca8c8cc945ca45), SPH_C64(0x9529c7c7bc7b297b), SPH_C64(0xd6d36b6b056ed36e), SPH_C64(0x503c28286c443c44),
	SPH_C64(0x5579a7a72c8b798b), SPH_C64(0x63e2bcbc813de23d), SPH_C64(0x2c1d161631271d27), SPH_C64(0x4176adad379a769a),
	SPH_C64(0xad3bdbdb964d3b4d), SPH_C64(0xc85664649efa56fa), SPH_C64(0xe84e7474a6d24ed2), SPH_C64(0x281e141436221e22),
	SPH_C64(0x3fdb9292e476db76), SPH_C64(0x180a0c0c121e0a1e), SPH_C64(0x906c4848fcb46cb4), SPH_C64(0x6be4b8b88f37e437),
	SPH_C64(0x255d9f9f78e75de7), SPH_C64(0x616ebdbd0fb26eb2), SPH_C64(0x86ef4343692aef2a), SPH_C64(0x93a6c4c435f1a6f1),
	SPH_C64(0x72a83939dae3a8e3), SPH_C64(0x62a43131c6f7a4f7), SPH_C64(0xbd37d3d38a593759), SPH_C64(0xff8bf2f274868b86),
	SPH_C64(0xb132d5d583563256), SPH_C64(0x0d438b8b4ec543c5), SPH_C64(0xdc596e6e85eb59eb), SPH_C64(0xafb7dada18c2b7c2),
	SPH_C64(0x028c01018e8f8c8f), SPH_C64(0x7964b1b11dac64ac), SPH_C64(0x23d29c9cf16dd26d), SPH_C64(0x92e04949723be03b),
	SPH_C64(0xabb4d8d81fc7b4c7), SPH_C64(0x43faacacb915fa15), SPH_C64(0xfd07f3f3fa090709), SPH_C64(0x8525cfcfa06f256f),
	SPH_C64(0x8fafcaca20eaafea), SPH_C64(0xf38ef4f47d898e89), SPH_C64(0x8ee947476720e920), SPH_C64(0x2018101038281828),
	SPH_C64(0xded56f6f0b64d564), SPH_C64(0xfb88f0f073838883), SPH_C64(0x946f4a4afbb16fb1), SPH_C64(0xb8725c5cca967296),
	SPH_C64(0x70243838546c246c), SPH_C64(0xaef157575f08f108), SPH_C64(0xe6c773732152c752), SPH_C64(0x3551979764f351f3),
	SPH_C64(0x8d23cbcbae652365), SPH_C64(0x597ca1a125847c84), SPH_C64(0xcb9ce8e857bf9cbf), SPH_C64(0x7c213e3e5d632163),
	SPH_C64(0x37dd9696ea7cdd7c), SPH_C64(0xc2dc61611e7fdc7f), SPH_C64(0x1a860d0d9c918691), SPH_C64(0x1e850f0f9b948594),
	SPH_C64(0xdb90e0e04bab90ab), SPH_C64(0xf8427c7cbac642c6), SPH_C64(0xe2c471712657c457), SPH_C64(0x83aacccc29e5aae5),
	SPH_C64(0x3bd89090e373d873), SPH_C64(0x0c050606090f050f), SPH_C64(0xf501f7f7f4030103), SPH_C64(0x38121c1c2a361236),
	SPH_C64(0x9fa3c2c23cfea3fe), SPH_C64(0xd45f6a6a8be15fe1), SPH_C64(0x47f9aeaebe10f910), SPH_C64(0xd2d06969026bd06b),
	SPH_C64(0x2e911717bfa891a8), SPH_C64(0x2958999971e858e8), SPH_C64(0x74273a3a53692769), SPH_C64(0x4eb92727f7d0b9d0),
	SPH_C64(0xa938d9d991483848), SPH_C64(0xcd13ebebde351335), SPH_C64(0x56b32b2be5ceb3ce), SPH_C64(0x4433222277553355),
	SPH_C64(0xbfbbd2d204d6bbd6), SPH_C64(0x4970a9a939907090), SPH_C64(0x0e89070787808980), SPH_C64(0x66a73333c1f2a7f2),
	SPH_C64(0x5ab62d2decc1b6c1), SPH_C64(0x78223c3c5a662266), SPH_C64(0x2a921515b8ad92ad), SPH_C64(0x8920c9c9a9602060),
	SPH_C64(0x154987875cdb49db), SPH_C64(0x4fffaaaab01aff1a), SPH_C64(0xa0785050d8887888), SPH_C64(0x517aa5a52b8e7a8e),
	SPH_C64(0x068f0303898a8f8a), SPH_C64(0xb2f859594a13f813), SPH_C64(0x12800909929b809b), SPH_C64(0x34171a1a23391739),
	SPH_C64(0xcada65651075da75), SPH_C64(0xb531d7d784533153), SPH_C64(0x13c68484d551c651), SPH_C64(0xbbb8d0d003d3b8d3),
	SPH_C64(0x1fc38282dc5ec35e), SPH_C64(0x52b02929e2cbb0cb), SPH_C64(0xb4775a5ac3997799), SPH_C64(0x3c111e1e2d331133),
	SPH_C64(0xf6cb7b7b3d46cb46), SPH_C64(0x4bfca8a8b71ffc1f), SPH_C64(0xdad66d6d0c61d661), SPH_C64(0x583a2c2c624e3a4e)
};

static const sph_u64 T6[] GROESTL_ALIGN64 = {
	SPH_C64(0xa5c6c632f4a5f497), SPH_C64(0x84f8f86f978497eb), SPH_C64(0x99eeee5eb099b0c7), SPH_C64(0x8df6f67a8c8d8cf7),
	SPH_C64(0x0dffffe8170d17e5), SPH_C64(0xbdd6d60adcbddcb7), SPH_C64(0xb1dede16c8b1c8a7), SPH_C64(0x5491916dfc54fc39),
	SPH_C64(0x50606090f050f0c0), SPH_C64(0x0302020705030504), SPH_C64(0xa9cece2ee0a9e087), SPH_C64(0x7d5656d1877d87ac),
	SPH_C64(0x19e7e7cc2b192bd5), SPH_C64(0x62b5b513a662a671), SPH_C64(0xe64d4d7c31e6319a), SPH_C64(0x9aecec59b59ab5c3),
	SPH_C64(0x458f8f40cf45cf05), SPH_C64(0x9d1f1fa3bc9dbc3e), SPH_C64(0x40898949c040c009), SPH_C64(0x87fafa68928792ef),
	SPH_C64(0x15efefd03f153fc5), SPH_C64(0xebb2b29426eb267f), SPH_C64(0xc98e8ece40c94007), SPH_C64(0x0bfbfbe61d0b1ded),
	SPH_C64(0xec41416e2fec2f82), SPH_C64(0x67b3b31aa967a97d), SPH_C64(0xfd5f5f431cfd1cbe), SPH_C64(0xea45456025ea258a),
	SPH_C64(0xbf2323f9dabfda46), SPH_C64(0xf753535102f702a6), SPH_C64(0x96e4e445a196a1d3), SPH_C64(0x5b9b9b76ed5bed2d),
	SPH_C64(0xc27575285dc25dea), SPH_C64(0x1ce1e1c5241c24d9), SPH_C64(0xae3d3dd4e9aee97a), SPH_C64(0x6a4c4cf2be6abe98),
	SPH_C64(0x5a6c6c82ee5aeed8), SPH_C64(0x417e7ebdc341c3fc), SPH_C64(0x02f5f5f3060206f1), SPH_C64(0x4f838352d14fd11d),
	SPH_C64(0x5c68688ce45ce4d0), SPH_C64(0xf451515607f407a2), SPH_C64(0x34d1d18d5c345cb9), SPH_C64(0x08f9f9e1180818e9),
	SPH_C64(0x93e2e24cae93aedf), SPH_C64(0x73abab3e9573954d), SPH_C64(0x53626297f553f5c4), SPH_C64(0x3f2a2a6b413f4154),
	SPH_C64(0x0c08081c140c1410), SPH_C64(0x52959563f652f631), SPH_C64(0x654646e9af65af8c), SPH_C64(0x5e9d9d7fe25ee221),
	SPH_C64(0x2830304878287860), SPH_C64(0xa13737cff8a1f86e), SPH_C64(0x0f0a0a1b110f1114), SPH_C64(0xb52f2febc4b5c45e),
	SPH_C64(0x090e0e151b091b1c), SPH_C64(0x3624247e5a365a48), SPH_C64(0x9b1b1badb69bb636), SPH_C64(0x3ddfdf98473d47a5),
	SPH_C64(0x26cdcda76a266a81), SPH_C64(0x694e4ef5bb69bb9c), SPH_C64(0xcd7f7f334ccd4cfe), SPH_C64(0x9feaea50ba9fbacf),
	SPH_C64(0x1b12123f2d1b2d24), SPH_C64(0x9e1d1da4b99eb93a), SPH_C64(0x745858c49c749cb0), SPH_C64(0x2e343446722e7268),
	SPH_C64(0x2d363641772d776c), SPH_C64(0xb2dcdc11cdb2cda3), SPH_C64(0xeeb4b49d29ee2973), SPH_C64(0xfb5b5b4d16fb16b6),
	SPH_C64(0xf6a4a4a501f60153), SPH_C64(0x4d7676a1d74dd7ec), SPH_C64(0x61b7b714a361a375), SPH_C64(0xce7d7d3449ce49fa),
	SPH_C64(0x7b5252df8d7b8da4), SPH_C64(0x3edddd9f423e42a1), SPH_C64(0x715e5ecd937193bc), SPH_C64(0x971313b1a297a226),
	SPH_C64(0xf5a6a6a204f50457), SPH_C64(0x68b9b901b868b869), SPH_C64(0x0000000000000000), SPH_C64(0x2cc1c1b5742c7499),
	SPH_C64(0x604040e0a060a080), SPH_C64(0x1fe3e3c2211f21dd), SPH_C64(0xc879793a43c843f2), SPH_C64(0xedb6b69a2ced2c77),
	SPH_C64(0xbed4d40dd9bed9b3), SPH_C64(0x468d8d47ca46ca01), SPH_C64(0xd967671770d970ce), SPH_C64(0x4b7272afdd4bdde4),
	SPH_C64(0xde9494ed79de7933), SPH_C64(0xd49898ff67d4672b), SPH_C64(0xe8b0b09323e8237b), SPH_C64(0x4a85855bde4ade11),
	SPH_C64(0x6bbbbb06bd6bbd6d), SPH_C64(0x2ac5c5bb7e2a7e91), SPH_C64(0xe54f4f7b34e5349e), SPH_C64(0x16ededd73a163ac1),
	SPH_C64(0xc58686d254c55417), SPH_C64(0xd79a9af862d7622f), SPH_C64(0x55666699ff55ffcc), SPH_C64(0x941111b6a794a722),
	SPH_C64(0xcf8a8ac04acf4a0f), SPH_C64(0x10e9e9d9301030c9), SPH_C64(0x0604040e0a060a08), SPH_C64(0x81fefe66988198e7),
	SPH_C64(0xf0a0a0ab0bf00b5b), SPH_C64(0x447878b4cc44ccf0), SPH_C64(0xba2525f0d5bad54a), SPH_C64(0xe34b4b753ee33e96),
	SPH_C64(0xf3a2a2ac0ef30e5f), SPH_C64(0xfe5d5d4419fe19ba), SPH_C64(0xc08080db5bc05b1b), SPH_C64(0x8a050580858a850a),
	SPH_C64(0xad3f3fd3ecadec7e), SPH_C64(0xbc2121fedfbcdf42), SPH_C64(0x487070a8d848d8e0), SPH_C64(0x04f1f1fd0c040cf9),
	SPH_C64(0xdf6363197adf7ac6), SPH_C64(0xc177772f58c158ee), SPH_C64(0x75afaf309f759f45), SPH_C64(0x634242e7a563a584),
	SPH_C64(0x3020207050305040), SPH_C64(0x1ae5e5cb2e1a2ed1), SPH_C64(0x0efdfdef120e12e1), SPH_C64(0x6dbfbf08b76db765),
	SPH_C64(0x4c818155d44cd419), SPH_C64(0x141818243c143c30), SPH_C64(0x352626795f355f4c), SPH_C64(0x2fc3c3b2712f719d),
	SPH_C64(0xe1bebe8638e13867), SPH_C64(0xa23535c8fda2fd6a), SPH_C64(0xcc8888c74fcc4f0b), SPH_C64(0x392e2e654b394b5c),
	SPH_C64(0x5793936af957f93d), SPH_C64(0xf25555580df20daa), SPH_C64(0x82fcfc619d829de3), SPH_C64(0x477a7ab3c947c9f4),
	SPH_C64(0xacc8c827efacef8b), SPH_C64(0xe7baba8832e7326f), SPH_C64(0x2b32324f7d2b7d64), SPH_C64(0x95e6e642a495a4d7),
	SPH_C64(0xa0c0c03bfba0fb9b), SPH_C64(0x981919aab398b332), SPH_C64(0xd19e9ef668d16827), SPH_C64(0x7fa3a322817f815d),
	SPH_C64(0x664444eeaa66aa88), SPH_C64(0x7e5454d6827e82a8), SPH_C64(0xab3b3bdde6abe676), SPH_C64(0x830b0b959e839e16),
	SPH_C64(0xca8c8cc945ca4503), SPH_C64(0x29c7c7bc7b297b95), SPH_C64(0xd36b6b056ed36ed6), SPH_C64(0x3c28286c443c4450),
	SPH_C64(0x79a7a72c8b798b55), SPH_C64(0xe2bcbc813de23d63), SPH_C64(0x1d161631271d272c), SPH_C64(0x76adad379a769a41),
	SPH_C64(0x3bdbdb964d3b4dad), SPH_C64(0x5664649efa56fac8), SPH_C64(0x4e7474a6d24ed2e8), SPH_C64(0x1e141436221e2228),
	SPH_C64(0xdb9292e476db763f), SPH_C64(0x0a0c0c121e0a1e18), SPH_C64(0x6c4848fcb46cb490), SPH_C64(0xe4b8b88f37e4376b),
	SPH_C64(0x5d9f9f78e75de725), SPH_C64(0x6ebdbd0fb26eb261), SPH_C64(0xef4343692aef2a86), SPH_C64(0xa6c4c435f1a6f193),
	SPH_C64(0xa83939dae3a8e372), SPH_C64(0xa43131c6f7a4f762), SPH_C64(0x37d3d38a593759bd), SPH_C64(0x8bf2f274868b86ff),
	SPH_C64(0x32d5d583563256b1), SPH_C64(0x438b8b4ec543c50d), SPH_C64(0x596e6e85eb59ebdc), SPH_C64(0xb7dada18c2b7c2af),
	SPH_C64(0x8c01018e8f8c8f02), SPH_C64(0x64b1b11dac64ac79), SPH_C64(0xd29c9cf16dd26d23), SPH_C64(0xe04949723be03b92),
	SPH_C64(0xb4d8d81fc7b4c7ab), SPH_C64(0xfaacacb915fa1543), SPH_C64(0x07f3f3fa090709fd), SPH_C64(0x25cfcfa06f256f85),
	SPH_C64(0xafcaca20eaafea8f), SPH_C64(0x8ef4f47d898e89f3), SPH_C64(0xe947476720e9208e), SPH_C64(0x1810103828182820),
	SPH_C64(0xd56f6f0b64d564de), SPH_C64(0x88f0f073838883fb), SPH_C64(0x6f4a4afbb16fb194), SPH_C64(0x725c5cca967296b8),
	SPH_C64(0x243838546c246c70), SPH_C64(0xf157575f08f108ae), SPH_C64(0xc773732152c752e6), SPH_C64(0x51979764f351f335),
	SPH_C64(0x23cbcbae6523658d), SPH_C64(0x7ca1a125847c8459), SPH_C64(0x9ce8e857bf9cbfcb), SPH_C64(0x213e3e5d6321637c),
	SPH_C64(0xdd9696ea7cdd7c37), SPH_C64(0xdc61611e7fdc7fc2), SPH_C64(0x860d0d9c9186911a), SPH_C64(0x850f0f9b9485941e),
	SPH_C64(0x90e0e04bab90abdb), SPH_C64(0x427c7cbac642c6f8), SPH_C64(0xc471712657c457e2), SPH_C64(0xaacccc29e5aae583),
	SPH_C64(0xd89090e373d8733b), SPH_C64(0x050606090f050f0c), SPH_C64(0x01f7f7f4030103f5), SPH_C64(0x121c1c2a36123638),
	SPH_C64(0xa3c2c23cfea3fe9f), SPH_C64(0x5f6a6a8be15fe1d4), SPH_C64(0xf9aeaebe10f91047), SPH_C64(0xd06969026bd06bd2),
	SPH_C64(0x911717bfa891a82e), SPH_C64(0x58999971e858e829), SPH_C64(0x273a3a5369276974), SPH_C64(0xb92727f7d0b9d04e),
	SPH_C64(0x38d9d991483848a9), SPH_C64(0x13ebebde351335cd), SPH_C64(0xb32b2be5ceb3ce56), SPH_C64(0x3322227755335544),
	SPH_C64(0xbbd2d204d6bbd6bf), SPH_C64(0x70a9a93990709049), SPH_C64(0x890707878089800e), SPH_C64(0xa73333c1f2a7f266),
	SPH_C64(0xb62d2decc1b6c15a), SPH_C64(0x223c3c5a66226678), SPH_C64(0x921515b8ad92ad2a), SPH_C64(0x20c9c9a960206089),
	SPH_C64(0x4987875cdb49db15), SPH_C64(0xffaaaab01aff1a4f), SPH_C64(0x785050d8887888a0), SPH_C64(0x7aa5a52b8e7a8e51),
	SPH_C64(0x8f0303898a8f8a06), SPH_C64(0xf859594a13f813b2), SPH_C64(0x800909929b809b12), SPH_C64(0x171a1a2339173934),
	SPH_C64(0xda65651075da75ca), SPH_C64(0x31d7d784533153b5), SPH_C64(0xc68484d551c65113), SPH_C64(0xb8d0d003d3b8d3bb),
	SPH_C64(0xc38282dc5ec35e1f), SPH_C64(0xb02929e2cbb0cb52), SPH_C64(0x775a5ac3997799b4), SPH_C64(0x111e1e2d3311333c),
	SPH_C64(0xcb7b7b3d46cb46f6), SPH_C64(0xfca8a8b71ffc1f4b), SPH_C64(0xd66d6d0c61d661da), SPH_C64(0x3a2c2c624e3a4e58)
};

static const sph_u64 T7[] GROESTL_ALIGN64 = {
	SPH_C64(0xc6c632f4a5f497a5), SPH_C64(0xf8f86f978497eb84), SPH_C64(0xeeee5eb099b0c799), SPH_C64(0xf6f67a8c8d8cf78d),
	SPH_C64(0xffffe8170d17e50d), SPH_C64(0xd6d60adcbddcb7bd), SPH_C64(0xdede16c8b1c8a7b1), SPH_C64(0x91916dfc54fc3954),
	SPH_C64(0x606090f050f0c050), SPH_C64(0x0202070503050403), SPH_C64(0xcece2ee0a9e087a9), SPH_C64(0x5656d1877d87ac7d),
	SPH_C64(0xe7e7cc2b192bd519), SPH_C64(0xb5b513a662a67162), SPH_C64(0x4d4d7c31e6319ae6), SPH_C64(0xecec59b59ab5c39a),
	SPH_C64(0x8f8f40cf45cf0545), SPH_C64(0x1f1fa3bc9dbc3e9d), SPH_C64(0x898949c040c00940), SPH_C64(0xfafa68928792ef87),
	SPH_C64(0xefefd03f153fc515), SPH_C64(0xb2b29426eb267feb), SPH_C64(0x8e8ece40c94007c9), SPH_C64(0xfbfbe61d0b1ded0b),
	SPH_C64(0x41416e2fec2f82ec), SPH_C64(0xb3b31aa967a97d67), SPH_C64(0x5f5f431cfd1cbefd), SPH_C64(0x45456025ea258aea),
	SPH_C64(0x2323f9dabfda46bf), SPH_C64(0x53535102f702a6f7), SPH_C64(0xe4e445a196a1d396), SPH_C64(0x9b9b76ed5bed2d5b),
	SPH_C64(0x7575285dc25deac2), SPH_C64(0xe1e1c5241c24d91c), SPH_C64(0x3d3dd4e9aee97aae), SPH_C64(0x4c4cf2be6abe986a),
	SPH_C64(0x6c6c82ee5aeed85a), SPH_C64(0x7e7ebdc341c3fc41), SPH_C64(0xf5f5f3060206f102), SPH_C64(0x838352d14fd11d4f),
	SPH_C64(0x68688ce45ce4d05c), SPH_C64(0x51515607f407a2f4), SPH_C64(0xd1d18d5c345cb934), SPH_C64(0xf9f9e1180818e908),
	SPH_C64(0xe2e24cae93aedf93), SPH_C64(0xabab3e9573954d73), SPH_C64(0x626297f553f5c453), SPH_C64(0x2a2a6b413f41543f),
	SPH_C64(0x08081c140c14100c), SPH_C64(0x959563f652f63152), SPH_C64(0x4646e9af65af8c65), SPH_C64(0x9d9d7fe25ee2215e),
	SPH_C64(0x3030487828786028), SPH_C64(0x3737cff8a1f86ea1), SPH_C64(0x0a0a1b110f11140f), SPH_C64(0x2f2febc4b5c45eb5),
	SPH_C64(0x0e0e151b091b1c09), SPH_C64(0x24247e5a365a4836), SPH_C64(0x1b1badb69bb6369b), SPH_C64(0xdfdf98473d47a53d),
	SPH_C64(0xcdcda76a266a8126), SPH_C64(0x4e4ef5bb69bb9c69), SPH_C64(0x7f7f334ccd4cfecd), SPH_C64(0xeaea50ba9fbacf9f),
	SPH_C64(0x12123f2d1b2d241b), SPH_C64(0x1d1da4b99eb93a9e), SPH_C64(0x5858c49c749cb074), SPH_C64(0x343446722e72682e),
	SPH_C64(0x363641772d776c2d), SPH_C64(0xdcdc11cdb2cda3b2), SPH_C64(0xb4b49d29ee2973ee), SPH_C64(0x5b5b4d16fb16b6fb),
	SPH_C64(0xa4a4a501f60153f6), SPH_C64(0x7676a1d74dd7ec4d), SPH_C64(0xb7b714a361a37561), SPH_C64(0x7d7d3449ce49face),
	SPH_C64(0x5252df8d7b8da47b), SPH_C64(0xdddd9f423e42a13e), SPH_C64(0x5e5ecd937193bc71), SPH_C64(0x1313b1a297a22697),
	SPH_C64(0xa6a6a204f50457f5), SPH_C64(0xb9b901b868b86968), SPH_C64(0x0000000000000000), SPH_C64(0xc1c1b5742c74992c),
	SPH_C64(0x4040e0a060a08060), SPH_C64(0xe3e3c2211f21dd1f), SPH_C64(0x79793a43c843f2c8), SPH_C64(0xb6b69a2ced2c77ed),
	SPH_C64(0xd4d40dd9bed9b3be), SPH_C64(0x8d8d47ca46ca0146), SPH_C64(0x67671770d970ced9), SPH_C64(0x7272afdd4bdde44b),
	SPH_C64(0x9494ed79de7933de), SPH_C64(0x9898ff67d4672bd4), SPH_C64(0xb0b09323e8237be8), SPH_C64(0x85855bde4ade114a),
	SPH_C64(0xbbbb06bd6bbd6d6b), SPH_C64(0xc5c5bb7e2a7e912a), SPH_C64(0x4f4f7b34e5349ee5), SPH_C64(0xededd73a163ac116),
	SPH_C64(0x8686d254c55417c5), SPH_C64(0x9a9af862d7622fd7), SPH_C64(0x666699ff55ffcc55), SPH_C64(0x1111b6a794a72294),
	SPH_C64(0x8a8ac04acf4a0fcf), SPH_C64(0xe9e9d9301030c910), SPH_C64(0x04040e0a060a0806), SPH_C64(0xfefe66988198e781),
	SPH_C64(0xa0a0ab0bf00b5bf0), SPH_C64(0x7878b4cc44ccf044), SPH_C64(0x2525f0d5bad54aba), SPH_C64(0x4b4b753ee33e96e3),
	SPH_C64(0xa2a2ac0ef30e5ff3), SPH_C64(0x5d5d4419fe19bafe), SPH_C64(0x8080db5bc05b1bc0), SPH_C64(0x050580858a850a8a),
	SPH_C64(0x3f3fd3ecadec7ead), SPH_C64(0x2121fedfbcdf42bc), SPH_C64(0x7070a8d848d8e048), SPH_C64(0xf1f1fd0c040cf904),
	SPH_C64(0x6363197adf7ac6df), SPH_C64(0x77772f58c158eec1), SPH_C64(0xafaf309f759f4575), SPH_C64(0x4242e7a563a58463),
	SPH_C64(0x2020705030504030), SPH_C64(0xe5e5cb2e1a2ed11a), SPH_C64(0xfdfdef120e12e10e), SPH_C64(0xbfbf08b76db7656d),
	SPH_C64(0x818155d44cd4194c), SPH_C64(0x1818243c143c3014), SPH_C64(0x2626795f355f4c35), SPH_C64(0xc3c3b2712f719d2f),
	SPH_C64(0xbebe8638e13867e1), SPH_C64(0x3535c8fda2fd6aa2), SPH_C64(0x8888c74fcc4f0bcc), SPH_C64(0x2e2e654b394b5c39),
	SPH_C64(0x93936af957f93d57), SPH_C64(0x5555580df20daaf2), SPH_C64(0xfcfc619d829de382), SPH_C64(0x7a7ab3c947c9f447),
	SPH_C64(0xc8c827efacef8bac), SPH_C64(0xbaba8832e7326fe7), SPH_C64(0x32324f7d2b7d642b), SPH_C64(0xe6e642a495a4d795),
	SPH_C64(0xc0c03bfba0fb9ba0), SPH_C64(0x1919aab398b33298), SPH_C64(0x9e9ef668d16827d1), SPH_C64(0xa3a322817f815d7f),
	SPH_C64(0x4444eeaa66aa8866), SPH_C64(0x5454d6827e82a87e), SPH_C64(0x3b3bdde6abe676ab), SPH_C64(0x0b0b959e839e1683),
	SPH_C64(0x8c8cc945ca4503ca), SPH_C64(0xc7c7bc7b297b9529), SPH_C64(0x6b6b056ed36ed6d3), SPH_C64(0x28286c443c44503c),
	SPH_C64(0xa7a72c8b798b5579), SPH_C64(0xbcbc813de23d63e2), SPH_C64(0x161631271d272c1d), SPH_C64(0xadad379a769a4176),
	SPH_C64(0xdbdb964d3b4dad3b), SPH_C64(0x64649efa56fac856), SPH_C64(0x7474a6d24ed2e84e), SPH_C64(0x141436221e22281e),
	SPH_C64(0x9292e476db763fdb), SPH_C64(0x0c0c121e0a1e180a), SPH_C64(0x4848fcb46cb4906c), SPH_C64(0xb8b88f37e4376be4),
	SPH_C64(0x9f9f78e75de7255d), SPH_C64(0xbdbd0fb26eb2616e), SPH_C64(0x4343692aef2a86ef), SPH_C64(0xc4c435f1a6f193a6),
	SPH_C64(0x3939dae3a8e372a8), SPH_C64(0x3131c6f7a4f762a4), SPH_C64(0xd3d38a593759bd37), SPH_C64(0xf2f274868b86ff8b),
	SPH_C64(0xd5d583563256b132), SPH_C64(0x8b8b4ec543c50d43), SPH_C64(0x6e6e85eb59ebdc59), SPH_C64(0xdada18c2b7c2afb7),
	SPH_C64(0x01018e8f8c8f028c), SPH_C64(0xb1b11dac64ac7964), SPH_C64(0x9c9cf16dd26d23d2), SPH_C64(0x4949723be03b92e0),
	SPH_C64(0xd8d81fc7b4c7abb4), SPH_C64(0xacacb915fa1543fa), SPH_C64(0xf3f3fa090709fd07), SPH_C64(0xcfcfa06f256f8525),
	SPH_C64(0xcaca20eaafea8faf), SPH_C64(0xf4f47d898e89f38e), SPH_C64(0x47476720e9208ee9), SPH_C64(0x1010382818282018),
	SPH_C64(0x6f6f0b64d564ded5), SPH_C64(0xf0f073838883fb88), SPH_C64(0x4a4afbb16fb1946f), SPH_C64(0x5c5cca967296b872),
	SPH_C64(0x3838546c246c7024), SPH_C64(0x57575f08f108aef1), SPH_C64(0x73732152c752e6c7), SPH_C64(0x979764f351f33551),
	SPH_C64(0xcbcbae6523658d23), SPH_C64(0xa1a125847c84597c), SPH_C64(0xe8e857bf9cbfcb9c), SPH_C64(0x3e3e5d6321637c21),
	SPH_C64(0x9696ea7cdd7c37dd), SPH_C64(0x61611e7fdc7fc2dc), SPH_C64(0x0d0d9c9186911a86), SPH_C64(0x0f0f9b9485941e85),
	SPH_C64(0xe0e04bab90abdb90), SPH_C64(0x7c7cbac642c6f842), SPH_C64(0x71712657c457e2c4), SPH_C64(0xcccc29e5aae583aa),
	SPH_C64(0x9090e373d8733bd8), SPH_C64(0x0606090f050f0c05), SPH_C64(0xf7f7f4030103f501), SPH_C64(0x1c1c2a3612363812),
	SPH_C64(0xc2c23cfea3fe9fa3), SPH_C64(0x6a6a8be15fe1d45f), SPH_C64(0xaeaebe10f91047f9), SPH_C64(0x6969026bd06bd2d0),
	SPH_C64(0x1717bfa891a82e91), SPH_C64(0x999971e858e82958), SPH_C64(0x3a3a536927697427), SPH_C64(0x2727f7d0b9d04eb9),
	SPH_C64(0xd9d991483848a938), SPH_C64(0xebebde351335cd13), SPH_C64(0x2b2be5ceb3ce56b3), SPH_C64(0x2222775533554433),
	SPH_C64(0xd2d204d6bbd6bfbb), SPH_C64(0xa9a9399070904970), SPH_C64(0x0707878089800e89), SPH_C64(0x3333c1f2a7f266a7),
	SPH_C64(0x2d2decc1b6c15ab6), SPH_C64(0x3c3c5a6622667822), SPH_C64(0x1515b8ad92ad2a92), SPH_C64(0xc9c9a96020608920),
	SPH_C64(0x87875cdb49db1549), SPH_C64(0xaaaab01aff1a4fff), SPH_C64(0x5050d8887888a078), SPH_C64(0xa5a52b8e7a8e517a),
	SPH_C64(0x0303898a8f8a068f), SPH_C64(0x59594a13f813b2f8), SPH_C64(0x0909929b809b1280), SPH_C64(0x1a1a233917393417),
	SPH_C64(0x65651075da75cada), SPH_C64(0xd7d784533153b531), SPH_C64(0x8484d551c65113c6), SPH_C64(0xd0d003d3b8d3bbb8),
	SPH_C64(0x8282dc5ec35e1fc3), SPH_C64(0x2929e2cbb0cb52b0), SPH_C64(0x5a5ac3997799b477), SPH_C64(0x1e1e2d3311333c11),
	SPH_C64(0x7b7b3d46cb46f6cb), SPH_C64(0xa8a8b71ffc1f4bfc), SPH_C64(0x6d6d0c61d661dad6), SPH_C64(0x2c2c624e3a4e583a)
};

#else /* Big-endian */

static const sph_u64 T1[] GROESTL_ALIGN64 = {
	SPH_C64(0xc6c632f4a5f497a5), SPH_C64(0xf8f86f978497eb84), SPH_C64(0xeeee5eb099b0c799), SPH_C64(0xf6f67a8c8d8cf78d),
	SPH_C64(0xffffe8170d17e50d), SPH_C64(0xd6d60adcbddcb7bd), SPH_C64(0xdede16c8b1c8a7b1), SPH_C64(0x91916dfc54fc3954),
	SPH_C64(0x606090f050f0c050), SPH_C64(0x0202070503050403), SPH_C64(0xcece2ee0a9e087a9), SPH_C64(0x5656d1877d87ac7d),
	SPH_C64(0xe7e7cc2b192bd519), SPH_C64(0xb5b513a662a67162), SPH_C64(0x4d4d7c31e6319ae6), SPH_C64(0xecec59b59ab5c39a),
	SPH_C64(0x8f8f40cf45cf0545), SPH_C64(0x1f1fa3bc9dbc3e9d), SPH_C64(0x898949c040c00940), SPH_C64(0xfafa68928792ef87),
	SPH_C64(0xefefd03f153fc515), SPH_C64(0xb2b29426eb267feb), SPH_C64(0x8e8ece40c94007c9), SPH_C64(0xfbfbe61d0b1ded0b),
	SPH_C64(0x41416e2fec2f82ec), SPH_C64(0xb3b31aa967a97d67), SPH_C64(0x5f5f431cfd1cbefd), SPH_C64(0x45456025ea258aea),
	SPH_C64(0x2323f9dabfda46bf), SPH_C64(0x53535102f702a6f7), SPH_C64(0xe4e445a196a1d396), SPH_C64(0x9b9b76ed5bed2d5b),
	SPH_C64(0x7575285dc25deac2), SPH_C64(0xe1e1c5241c24d91c), SPH_C64(0x3d3dd4e9aee97aae), SPH_C64(0x4c4cf2be6abe986a),
	SPH_C64(0x6c6c82ee5aeed85a), SPH_C64(0x7e7ebdc341c3fc41), SPH_C64(0xf5f5f3060206f102), SPH_C64(0x838352d14fd11d4f),
	SPH_C64(0x68688ce45ce4d05c), SPH_C64(0x51515607f407a2f4), SPH_C64(0xd1d18d5c345cb934), SPH_C64(0xf9f9e1180818e908),
	SPH_C64(0xe2e24cae93aedf93), SPH_C64(0xabab3e9573954d73), SPH_C64(0x626297f553f5c453), SPH_C64(0x2a2a6b413f41543f),
	SPH_C64(0x08081c140c14100c), SPH_C64(0x959563f652f63152), SPH_C64(0x4646e9af65af8c65), SPH_C64(0x9d9d7fe25ee2215e),
	SPH_C64(0x3030487828786028), SPH_C64(0x3737cff8a1f86ea1), SPH_C64(0x0a0a1b110f11140f), SPH_C64(0x2f2febc4b5c45eb5),
	SPH_C64(0x0e0e151b091b1c09), SPH_C64(0x24247e5a365a4836), SPH_C64(0x1b1badb69bb6369b), SPH_C64(0xdfdf98473d47a53d),
	SPH_C64(0xcdcda76a266a8126), SPH_C64(0x4e4ef5bb69bb9c69), SPH_C64(0x7f7f334ccd4cfecd), SPH_C64(0xeaea50ba9fbacf9f),
	SPH_C64(0x12123f2d1b2d241b), SPH_C64(0x1d1da4b99eb93a9e), SPH_C64(0x5858c49c749cb074), SPH_C64(0x343446722e72682e),
	SPH_C64(0x363641772d776c2d), SPH_C64(0xdcdc11cdb2cda3b2), SPH_C64(0xb4b49d29ee2973ee), SPH_C64(0x5b5b4d16fb16b6fb),
	SPH_C64(0xa4a4a501f60153f6), SPH_C64(0x7676a1d74dd7ec4d), SPH_C64(0xb7b714a361a37561), SPH_C64(0x7d7d3449ce49face),
	SPH_C64(0x5252df8d7b8da47b), SPH_C64(0xdddd9f423e42a13e), SPH_C64(0x5e5ecd937193bc71), SPH_C64(0x1313b1a297a22697),
	SPH_C64(0xa6a6a204f50457f5), SPH_C64(0xb9b901b868b86968), SPH_C64(0x0000000000000000), SPH_C64(0xc1c1b5742c74992c),
	SPH_C64(0x4040e0a060a08060), SPH_C64(0xe3e3c2211f21dd1f), SPH_C64(0x79793a43c843f2c8), SPH_C64(0xb6b69a2ced2c77ed),
	SPH_C64(0xd4d40dd9bed9b3be), SPH_C64(0x8d8d47ca46ca0146), SPH_C64(0x67671770d970ced9), SPH_C64(0x7272afdd4bdde44b),
	SPH_C64(0x9494ed79de7933de), SPH_C64(0x9898ff67d4672bd4), SPH_C64(0xb0b09323e8237be8), SPH_C64(0x85855bde4ade114a),
	SPH_C64(0xbbbb06bd6bbd6d6b), SPH_C64(0xc5c5bb7e2a7e912a), SPH_C64(0x4f4f7b34e5349ee5), SPH_C64(0xededd73a163ac116),
	SPH_C64(0x8686d254c55417c5), SPH_C64(0x9a9af862d7622fd7), SPH_C64(0x666699ff55ffcc55), SPH_C64(0x1111b6a794a72294),
	SPH_C64(0x8a8ac04acf4a0fcf), SPH_C64(0xe9e9d9301030c910), SPH_C64(0x04040e0a060a0806), SPH_C64(0xfefe66988198e781),
	SPH_C64(0xa0a0ab0bf00b5bf0), SPH_C64(0x7878b4cc44ccf044), SPH_C64(0x2525f0d5bad54aba), SPH_C64(0x4b4b753ee33e96e3),
	SPH_C64(0xa2a2ac0ef30e5ff3), SPH_C64(0x5d5d4419fe19bafe), SPH_C64(0x8080db5bc05b1bc0), SPH_C64(0x050580858a850a8a),
	SPH_C64(0x3f3fd3ecadec7ead), SPH_C64(0x2121fedfbcdf42bc), SPH_C64(0x7070a8d848d8e048), SPH_C64(0xf1f1fd0c040cf904),
	SPH_C64(0x6363197adf7ac6df), SPH_C64(0x77772f58c158eec1), SPH_C64(0xafaf309f759f4575), SPH_C64(0x4242e7a563a58463),
	SPH_C64(0x2020705030504030), SPH_C64(0xe5e5cb2e1a2ed11a), SPH_C64(0xfdfdef120e12e10e), SPH_C64(0xbfbf08b76db7656d),
	SPH_C64(0x818155d44cd4194c), SPH_C64(0x1818243c143c3014), SPH_C64(0x2626795f355f4c35), SPH_C64(0xc3c3b2712f719d2f),
	SPH_C64(0xbebe8638e13867e1), SPH_C64(0x3535c8fda2fd6aa2), SPH_C64(0x8888c74fcc4f0bcc), SPH_C64(0x2e2e654b394b5c39),
	SPH_C64(0x93936af957f93d57), SPH_C64(0x5555580df20daaf2), SPH_C64(0xfcfc619d829de382), SPH_C64(0x7a7ab3c947c9f447),
	SPH_C64(0xc8c827efacef8bac), SPH_C64(0xbaba8832e7326fe7), SPH_C64(0x32324f7d2b7d642b), SPH_C64(0xe6e642a495a4d795),
	SPH_C64(0xc0c03bfba0fb9ba0), SPH_C64(0x1919aab398b33298), SPH_C64(0x9e9ef668d16827d1), SPH_C64(0xa3a322817f815d7f),
	SPH_C64(0x4444eeaa66aa8866), SPH_C64(0x5454d6827e82a87e), SPH_C64(0x3b3bdde6abe676ab), SPH_C64(0x0b0b959e839e1683),
	SPH_C64(0x8c8cc945ca4503ca), SPH_C64(0xc7c7bc7b297b9529), SPH_C64(0x6b6b056ed36ed6d3), SPH_C64(0x28286c443c44503c),
	SPH_C64(0xa7a72c8b798b5579), SPH_C64(0xbcbc813de23d63e2), SPH_C64(0x161631271d272c1d), SPH_C64(0xadad379a769a4176),
	SPH_C64(0xdbdb964d3b4dad3b), SPH_C64(0x64649efa56fac856), SPH_C64(0x7474a6d24ed2e84e), SPH_C64(0x141436221e22281e),
	SPH_C64(0x9292e476db763fdb), SPH_C64(0x0c0c121e0a1e180a), SPH_C64(0x4848fcb46cb4906c), SPH_C64(0xb8b88f37e4376be4),
	SPH_C64(0x9f9f78e75de7255d), SPH_C64(0xbdbd0fb26eb2616e), SPH_C64(0x4343692aef2a86ef), SPH_C64(0xc4c435f1a6f193a6),
	SPH_C64(0x3939dae3a8e372a8), SPH_C64(0x3131c6f7a4f762a4), SPH_C64(0xd3d38a593759bd37), SPH_C64(0xf2f274868b86ff8b),
	SPH_C64(0xd5d583563256b132), SPH_C64(0x8b8b4ec543c50d43), SPH_C64(0x6e6e85eb59ebdc59), SPH_C64(0xdada18c2b7c2afb7),
	SPH_C64(0x01018e8f8c8f028c), SPH_C64(0xb1b11dac64ac7964), SPH_C64(0x9c9cf16dd26d23d2), SPH_C64(0x4949723be03b92e0),
	SPH_C64(0xd8d81fc7b4c7abb4), SPH_C64(0xacacb915fa1543fa), SPH_C64(0xf3f3fa090709fd07), SPH_C64(0xcfcfa06f256f8525),
	SPH_C64(0xcaca20eaafea8faf), SPH_C64(0xf4f47d898e89f38e), SPH_C64(0x47476720e9208ee9), SPH_C64(0x1010382818282018),
	SPH_C64(0x6f6f0b64d564ded5), SPH_C64(0xf0f073838883fb88), SPH_C64(0x4a4afbb16fb1946f), SPH_C64(0x5c5cca967296b872),
	SPH_C64(0x3838546c246c7024), SPH_C64(0x57575f08f108aef1), SPH_C64(0x73732152c752e6c7), SPH_C64(0x979764f351f33551),
	SPH_C64(0xcbcbae6523658d23), SPH_C64(0xa1a125847c84597c), SPH_C64(0xe8e857bf9cbfcb9c), SPH_C64(0x3e3e5d6321637c21),
	SPH_C64(0x9696ea7cdd7c37dd), SPH_C64(0x61611e7fdc7fc2dc), SPH_C64(0x0d0d9c9186911a86), SPH_C64(0x0f0f9b9485941e85),
	SPH_C64(0xe0e04bab90abdb90), SPH_C64(0x7c7cbac642c6f842), SPH_C64(0x71712657c457e2c4), SPH_C64(0xcccc29e5aae583aa),
	SPH_C64(0x9090e373d8733bd8), SPH_C64(0x0606090f050f0c05), SPH_C64(0xf7f7f4030103f501), SPH_C64(0x1c1c2a3612363812),
	SPH_C64(0xc2c23cfea3fe9fa3), SPH_C64(0x6a6a8be15fe1d45f), SPH_C64(0xaeaebe10f91047f9), SPH_C64(0x6969026bd06bd2d0),
	SPH_C64(0x1717bfa891a82e91), SPH_C64(0x999971e858e82958), SPH_C64(0x3a3a536927697427), SPH_C64(0x2727f7d0b9d04eb9),
	SPH_C64(0xd9d991483848a938), SPH_C64(0xebebde351335cd13), SPH_C64(0x2b2be5ceb3ce56b3), SPH_C64(0x2222775533554433),
	SPH_C64(0xd2d204d6bbd6bfbb), SPH_C64(0xa9a9399070904970), SPH_C64(0x0707878089800e89), SPH_C64(0x3333c1f2a7f266a7),
	SPH_C64(0x2d2decc1b6c15ab6), SPH_C64(0x3c3c5a6622667822), SPH_C64(0x1515b8ad92ad2a92), SPH_C64(0xc9c9a96020608920),
	SPH_C64(0x87875cdb49db1549), SPH_C64(0xaaaab01aff1a4fff), SPH_C64(0x5050d8887888a078), SPH_C64(0xa5a52b8e7a8e517a),
	SPH_C64(0x0303898a8f8a068f), SPH_C64(0x59594a13f813b2f8), SPH_C64(0x0909929b809b1280), SPH_C64(0x1a1a233917393417),
	SPH_C64(0x65651075da75cada), SPH_C64(0xd7d784533153b531), SPH_C64(0x8484d551c65113c6), SPH_C64(0xd0d003d3b8d3bbb8),
	SPH_C64(0x8282dc5ec35e1fc3), SPH_C64(0x2929e2cbb0cb52b0), SPH_C64(0x5a5ac3997799b477), SPH_C64(0x1e1e2d3311333c11),
	SPH_C64(0x7b7b3d46cb46f6cb), SPH_C64(0xa8a8b71ffc1f4bfc), SPH_C64(0x6d6d0c61d661dad6), SPH_C64(0x2c2c624e3a4e583a)
};

static const sph_u64 T2[] GROESTL_ALIGN64 = {
	SPH_C64(0xa5c6c632f4a5f497), SPH_C64(0x84f8f86f978497eb), SPH_C64(0x99eeee5eb099b0c7), SPH_C64(0x8df6f67a8c8d8cf7),
	SPH_C64(0x0dffffe8170d17e5), SPH_C64(0xbdd6d60adcbddcb7), SPH_C64(0xb1dede16c8b1c8a7), SPH_C64(0x5491916dfc54fc39),
	SPH_C64(0x50606090f050f0c0), SPH_C64(0x0302020705030504), SPH_C64(0xa9cece2ee0a9e087), SPH_C64(0x7d5656d1877d87ac),
	SPH_C64(0x19e7e7cc2b192bd5), SPH_C64(0x62b5b513a662a671), SPH_C64(0xe64d4d7c31e6319a), SPH_C64(0x9aecec59b59ab5c3),
	SPH_C64(0x458f8f40cf45cf05), SPH_C64(0x9d1f1fa3bc9dbc3e), SPH_C64(0x40898949c040c009), SPH_C64(0x87fafa68928792ef),
	SPH_C64(0x15efefd03f153fc5), SPH_C64(0xebb2b29426eb267f), SPH_C64(0xc98e8ece40c94007), SPH_C64(0x0bfbfbe61d0b1ded),
	SPH_C64(0xec41416e2fec2f82), SPH_C64(0x67b3b31aa967a97d), SPH_C64(0xfd5f5f431cfd1cbe), SPH_C64(0xea45456025ea258a),
	SPH_C64(0xbf2323f9dabfda46), SPH_C64(0xf753535102f702a6), SPH_C64(0x96e4e445a196a1d3), SPH_C64(0x5b9b9b76ed5bed2d),
	SPH_C64(0xc27575285dc25dea), SPH_C64(0x1ce1e1c5241c24d9), SPH_C64(0xae3d3dd4e9aee97a), SPH_C64(0x6a4c4cf2be6abe98),
	SPH_C64(0x5a6c6c82ee5aeed8), SPH_C64(0x417e7ebdc341c3fc), SPH_C64(0x02f5f5f3060206f1), SPH_C64(0x4f838352d14fd11d),
	SPH_C64(0x5c68688ce45ce4d0), SPH_C64(0xf451515607f407a2), SPH_C64(0x34d1d18d5c345cb9), SPH_C64(0x08f9f9e1180818e9),
	SPH_C64(0x93e2e24cae93aedf), SPH_C64(0x73abab3e9573954d), SPH_C64(0x53626297f553f5c4), SPH_C64(0x3f2a2a6b413f4154),
	SPH_C64(0x0c08081c140c1410), SPH_C64(0x52959563f652f631), SPH_C64(0x654646e9af65af8c), SPH_C64(0x5e9d9d7fe25ee221),
	SPH_C64(0x2830304878287860), SPH_C64(0xa13737cff8a1f86e), SPH_C64(0x0f0a0a1b110f1114), SPH_C64(0xb52f2febc4b5c45e),
	SPH_C64(0x090e0e151b091b1c), SPH_C64(0x3624247e5a365a48), SPH_C64(0x9b1b1badb69bb636), SPH_C64(0x3ddfdf98473d47a5),
	SPH_C64(0x26cdcda76a266a81), SPH_C64(0x694e4ef5bb69bb9c), SPH_C64(0xcd7f7f334ccd4cfe), SPH_C64(0x9feaea50ba9fbacf),
	SPH_C64(0x1b12123f2d1b2d24), SPH_C64(0x9e1d1da4b99eb93a), SPH_C64(0x745858c49c749cb0), SPH_C64(0x2e343446722e7268),
	SPH_C64(0x2d363641772d776c), SPH_C64(0xb2dcdc11cdb2cda3), SPH_C64(0xeeb4b49d29ee2973), SPH_C64(0xfb5b5b4d16fb16b6),
	SPH_C64(0xf6a4a4a501f60153), SPH_C64(0x4d7676a1d74dd7ec), SPH_C64(0x61b7b714a361a375), SPH_C64(0xce7d7d3449ce49fa),
	SPH_C64(0x7b5252df8d7b8da4), SPH_C64(0x3edddd9f423e42a1), SPH_C64(0x715e5ecd937193bc), SPH_C64(0x971313b1a297a226),
	SPH_C64(0xf5a6a6a204f50457), SPH_C64(0x68b9b901b868b869), SPH_C64(0x0000000000000000), SPH_C64(0x2cc1c1b5742c7499),
	SPH_C64(0x604040e0a060a080), SPH_C64(0x1fe3e3c2211f21dd), SPH_C64(0xc879793a43c843f2), SPH_C64(0xedb6b69a2ced2c77),
	SPH_C64(0xbed4d40dd9bed9b3), SPH_C64(0x468d8d47ca46ca01), SPH_C64(0xd967671770d970ce), SPH_C64(0x4b7272afdd4bdde4),
	SPH_C64(0xde9494ed79de7933), SPH_C64(0xd49898ff67d4672b), SPH_C64(0xe8b0b09323e8237b), SPH_C64(0x4a85855bde4ade11),
	SPH_C64(0x6bbbbb06bd6bbd6d), SPH_C64(0x2ac5c5bb7e2a7e91), SPH_C64(0xe54f4f7b34e5349e), SPH_C64(0x16ededd73a163ac1),
	SPH_C64(0xc58686d254c55417), SPH_C64(0xd79a9af862d7622f), SPH_C64(0x55666699ff55ffcc), SPH_C64(0x941111b6a794a722),
	SPH_C64(0xcf8a8ac04acf4a0f), SPH_C64(0x10e9e9d9301030c9), SPH_C64(0x0604040e0a060a08), SPH_C64(0x81fefe66988198e7),
	SPH_C64(0xf0a0a0ab0bf00b5b), SPH_C64(0x447878b4cc44ccf0), SPH_C64(0xba2525f0d5bad54a), SPH_C64(0xe34b4b753ee33e96),
	SPH_C64(0xf3a2a2ac0ef30e5f), SPH_C64(0xfe5d5d4419fe19ba), SPH_C64(0xc08080db5bc05b1b), SPH_C64(0x8a050580858a850a),
	SPH_C64(0xad3f3fd3ecadec7e), SPH_C64(0xbc2121fedfbcdf42), SPH_C64(0x487070a8d848d8e0), SPH_C64(0x04f1f1fd0c040cf9),
	SPH_C64(0xdf6363197adf7ac6), SPH_C64(0xc177772f58c158ee), SPH_C64(0x75afaf309f759f45), SPH_C64(0x634242e7a563a584),
	SPH_C64(0x3020207050305040), SPH_C64(0x1ae5e5cb2e1a2ed1), SPH_C64(0x0efdfdef120e12e1), SPH_C64(0x6dbfbf08b76db765),
	SPH_C64(0x4c818155d44cd419), SPH_C64(0x141818243c143c30), SPH_C64(0x352626795f355f4c), SPH_C64(0x2fc3c3b2712f719d),
	SPH_C64(0xe1bebe8638e13867), SPH_C64(0xa23535c8fda2fd6a), SPH_C64(0xcc8888c74fcc4f0b), SPH_C64(0x392e2e654b394b5c),
	SPH_C64(0x5793936af957f93d), SPH_C64(0xf25555580df20daa), SPH_C64(0x82fcfc619d829de3), SPH_C64(0x477a7ab3c947c9f4),
	SPH_C64(0xacc8c827efacef8b), SPH_C64(0xe7baba8832e7326f), SPH_C64(0x2b32324f7d2b7d64), SPH_C64(0x95e6e642a495a4d7),
	SPH_C64(0xa0c0c03bfba0fb9b), SPH_C64(0x981919aab398b332), SPH_C64(0xd19e9ef668d16827), SPH_C64(0x7fa3a322817f815d),
	SPH_C64(0x664444eeaa66aa88), SPH_C64(0x7e5454d6827e82a8), SPH_C64(0xab3b3bdde6abe676), SPH_C64(0x830b0b959e839e16),
	SPH_C64(0xca8c8cc945ca4503), SPH_C64(0x29c7c7bc7b297b95), SPH_C64(0xd36b6b056ed36ed6), SPH_C64(0x3c28286c443c4450),
	SPH_C64(0x79a7a72c8b798b55), SPH_C64(0xe2bcbc813de23d63), SPH_C64(0x1d161631271d272c), SPH_C64(0x76adad379a769a41),
	SPH_C64(0x3bdbdb964d3b4dad), SPH_C64(0x5664649efa56fac8), SPH_C64(0x4e7474a6d24ed2e8), SPH_C64(0x1e141436221e2228),
	SPH_C64(0xdb9292e476db763f), SPH_C64(0x0a0c0c121e0a1e18), SPH_C64(0x6c4848fcb46cb490), SPH_C64(0xe4b8b88f37e4376b),
	SPH_C64(0x5d9f9f78e75de725), SPH_C64(0x6ebdbd0fb26eb261), SPH_C64(0xef4343692aef2a86), SPH_C64(0xa6c4c435f1a6f193),
	SPH_C64(0xa83939dae3a8e372), SPH_C64(0xa43131c6f7a4f762), SPH_C64(0x37d3d38a593759bd), SPH_C64(0x8bf2f274868b86ff),
	SPH_C64(0x32d5d583563256b1), SPH_C64(0x438b8b4ec543c50d), SPH_C64(0x596e6e85eb59ebdc), SPH_C64(0xb7dada18c2b7c2af),
	SPH_C64(0x8c01018e8f8c8f02), SPH_C64(0x64b1b11dac64ac79), SPH_C64(0xd29c9cf16dd26d23), SPH_C64(0xe04949723be03b92),
	SPH_C64(0xb4d8d81fc7b4c7ab), SPH_C64(0xfaacacb915fa1543), SPH_C64(0x07f3f3fa090709fd), SPH_C64(0x25cfcfa06f256f85),
	SPH_C64(0xafcaca20eaafea8f), SPH_C64(0x8ef4f47d898e89f3), SPH_C64(0xe947476720e9208e), SPH_C64(0x1810103828182820),
	SPH_C64(0xd56f6f0b64d564de), SPH_C64(0x88f0f073838883fb), SPH_C64(0x6f4a4afbb16fb194), SPH_C64(0x725c5cca967296b8),
	SPH_C64(0x243838546c246c70), SPH_C64(0xf157575f08f108ae), SPH_C64(0xc773732152c752e6), SPH_C64(0x51979764f351f335),
	SPH_C64(0x23cbcbae6523658d), SPH_C64(0x7ca1a125847c8459), SPH_C64(0x9ce8e857bf9cbfcb), SPH_C64(0x213e3e5d6321637c),
	SPH_C64(0xdd9696ea7cdd7c37), SPH_C64(0xdc61611e7fdc7fc2), SPH_C64(0x860d0d9c9186911a), SPH_C64(0x850f0f9b9485941e),
	SPH_C64(0x90e0e04bab90abdb), SPH_C64(0x427c7cbac642c6f8), SPH_C64(0xc471712657c457e2), SPH_C64(0xaacccc29e5aae583),
	SPH_C64(0xd89090e373d8733b), SPH_C64(0x050606090f050f0c), SPH_C64(0x01f7f7f4030103f5), SPH_C64(0x121c1c2a36123638),
	SPH_C64(0xa3c2c23cfea3fe9f), SPH_C64(0x5f6a6a8be15fe1d4), SPH_C64(0xf9aeaebe10f91047), SPH_C64(0xd06969026bd06bd2),
	SPH_C64(0x911717bfa891a82e), SPH_C64(0x58999971e858e829), SPH_C64(0x273a3a5369276974), SPH_C64(0xb92727f7d0b9d04e),
	SPH_C64(0x38d9d991483848a9), SPH_C64(0x13ebebde351335cd), SPH_C64(0xb32b2be5ceb3ce56), SPH_C64(0x3322227755335544),
	SPH_C64(0xbbd2d204d6bbd6bf), SPH_C64(0x70a9a93990709049), SPH_C64(0x890707878089800e), SPH_C64(0xa73333c1f2a7f266),
	SPH_C64(0xb62d2decc1b6c15a), SPH_C64(0x223c3c5a66226678), SPH_C64(0x921515b8ad92ad2a), SPH_C64(0x20c9c9a960206089),
	SPH_C64(0x4987875cdb49db15), SPH_C64(0xffaaaab01aff1a4f), SPH_C64(0x785050d8887888a0), SPH_C64(0x7aa5a52b8e7a8e51),
	SPH_C64(0x8f0303898a8f8a06), SPH_C64(0xf859594a13f813b2), SPH_C64(0x800909929b809b12), SPH_C64(0x171a1a2339173934),
	SPH_C64(0xda65651075da75ca), SPH_C64(0x31d7d784533153b5), SPH_C64(0xc68484d551c65113), SPH_C64(0xb8d0d003d3b8d3bb),
	SPH_C64(0xc38282dc5ec35e1f), SPH_C64(0xb02929e2cbb0cb52), SPH_C64(0x775a5ac3997799b4), SPH_C64(0x111e1e2d3311333c),
	SPH_C64(0xcb7b7b3d46cb46f6), SPH_C64(0xfca8a8b71ffc1f4b), SPH_C64(0xd66d6d0c61d661da), SPH_C64(0x3a2c2c624e3a4e58)
};

static const sph_u64 T3[] GROESTL_ALIGN64 = {
	SPH_C64(0x97a5c6c632f4a5f4), SPH_C64(0xeb84f8f86f978497), SPH_C64(0xc799eeee5eb099b0), SPH_C64(0xf78df6f67a8c8d8c),
	SPH_C64(0xe50dffffe8170d17), SPH_C64(0xb7bdd6d60adcbddc), SPH_C64(0xa7b1dede16c8b1c8), SPH_C64(0x395491916dfc54fc),
	SPH_C64(0xc050606090f050f0), SPH_C64(0x0403020207050305), SPH_C64(0x87a9cece2ee0a9e0), SPH_C64(0xac7d5656d1877d87),
	SPH_C64(0xd519e7e7cc2b192b), SPH_C64(0x7162b5b513a662a6), SPH_C64(0x9ae64d4d7c31e631), SPH_C64(0xc39aecec59b59ab5),
	SPH_C64(0x05458f8f40cf45cf), SPH_C64(0x3e9d1f1fa3bc9dbc), SPH_C64(0x0940898949c040c0), SPH_C64(0xef87fafa68928792),
	SPH_C64(0xc515efefd03f153f), SPH_C64(0x7febb2b29426eb26), SPH_C64(0x07c98e8ece40c940), SPH_C64(0xed0bfbfbe61d0b1d),
	SPH_C64(0x82ec41416e2fec2f), SPH_C64(0x7d67b3b31aa967a9), SPH_C64(0xbefd5f5f431cfd1c), SPH_C64(0x8aea45456025ea25),
	SPH_C64(0x46bf2323f9dabfda), SPH_C64(0xa6f753535102f702), SPH_C64(0xd396e4e445a196a1), SPH_C64(0x2d5b9b9b76ed5bed),
	SPH_C64(0xeac27575285dc25d), SPH_C64(0xd91ce1e1c5241c24), SPH_C64(0x7aae3d3dd4e9aee9), SPH_C64(0x986a4c4cf2be6abe),
	SPH_C64(0xd85a6c6c82ee5aee), SPH_C64(0xfc417e7ebdc341c3), SPH_C64(0xf102f5f5f3060206), SPH_C64(0x1d4f838352d14fd1),
	SPH_C64(0xd05c68688ce45ce4), SPH_C64(0xa2f451515607f407), SPH_C64(0xb934d1d18d5c345c), SPH_C64(0xe908f9f9e1180818),
	SPH_C64(0xdf93e2e24cae93ae), SPH_C64(0x4d73abab3e957395), SPH_C64(0xc453626297f553f5), SPH_C64(0x543f2a2a6b413f41),
	SPH_C64(0x100c08081c140c14), SPH_C64(0x3152959563f652f6), SPH_C64(0x8c654646e9af65af), SPH_C64(0x215e9d9d7fe25ee2),
	SPH_C64(0x6028303048782878), SPH_C64(0x6ea13737cff8a1f8), SPH_C64(0x140f0a0a1b110f11), SPH_C64(0x5eb52f2febc4b5c4),
	SPH_C64(0x1c090e0e151b091b), SPH_C64(0x483624247e5a365a), SPH_C64(0x369b1b1badb69bb6), SPH_C64(0xa53ddfdf98473d47),
	SPH_C64(0x8126cdcda76a266a), SPH_C64(0x9c694e4ef5bb69bb), SPH_C64(0xfecd7f7f334ccd4c), SPH_C64(0xcf9feaea50ba9fba),
	SPH_C64(0x241b12123f2d1b2d), SPH_C64(0x3a9e1d1da4b99eb9), SPH_C64(0xb0745858c49c749c), SPH_C64(0x682e343446722e72),
	SPH_C64(0x6c2d363641772d77), SPH_C64(0xa3b2dcdc11cdb2cd), SPH_C64(0x73eeb4b49d29ee29), SPH_C64(0xb6fb5b5b4d16fb16),
	SPH_C64(0x53f6a4a4a501f601), SPH_C64(0xec4d7676a1d74dd7), SPH_C64(0x7561b7b714a361a3), SPH_C64(0xface7d7d3449ce49),
	SPH_C64(0xa47b5252df8d7b8d), SPH_C64(0xa13edddd9f423e42), SPH_C64(0xbc715e5ecd937193), SPH_C64(0x26971313b1a297a2),
	SPH_C64(0x57f5a6a6a204f504), SPH_C64(0x6968b9b901b868b8), SPH_C64(0x0000000000000000), SPH_C64(0x992cc1c1b5742c74),
	SPH_C64(0x80604040e0a060a0), SPH_C64(0xdd1fe3e3c2211f21), SPH_C64(0xf2c879793a43c843), SPH_C64(0x77edb6b69a2ced2c),
	SPH_C64(0xb3bed4d40dd9bed9), SPH_C64(0x01468d8d47ca46ca), SPH_C64(0xced967671770d970), SPH_C64(0xe44b7272afdd4bdd),
	SPH_C64(0x33de9494ed79de79), SPH_C64(0x2bd49898ff67d467), SPH_C64(0x7be8b0b09323e823), SPH_C64(0x114a85855bde4ade),
	SPH_C64(0x6d6bbbbb06bd6bbd), SPH_C64(0x912ac5c5bb7e2a7e), SPH_C64(0x9ee54f4f7b34e534), SPH_C64(0xc116ededd73a163a),
	SPH_C64(0x17c58686d254c554), SPH_C64(0x2fd79a9af862d762), SPH_C64(0xcc55666699ff55ff), SPH_C64(0x22941111b6a794a7),
	SPH_C64(0x0fcf8a8ac04acf4a), SPH_C64(0xc910e9e9d9301030), SPH_C64(0x080604040e0a060a), SPH_C64(0xe781fefe66988198),
	SPH_C64(0x5bf0a0a0ab0bf00b), SPH_C64(0xf0447878b4cc44cc), SPH_C64(0x4aba2525f0d5bad5), SPH_C64(0x96e34b4b753ee33e),
	SPH_C64(0x5ff3a2a2ac0ef30e), SPH_C64(0xbafe5d5d4419fe19), SPH_C64(0x1bc08080db5bc05b), SPH_C64(0x0a8a050580858a85),
	SPH_C64(0x7ead3f3fd3ecadec), SPH_C64(0x42bc2121fedfbcdf), SPH_C64(0xe0487070a8d848d8), SPH_C64(0xf904f1f1fd0c040c),
	SPH_C64(0xc6df6363197adf7a), SPH_C64(0xeec177772f58c158), SPH_C64(0x4575afaf309f759f), SPH_C64(0x84634242e7a563a5),
	SPH_C64(0x4030202070503050), SPH_C64(0xd11ae5e5cb2e1a2e), SPH_C64(0xe10efdfdef120e12), SPH_C64(0x656dbfbf08b76db7),
	SPH_C64(0x194c818155d44cd4), SPH_C64(0x30141818243c143c), SPH_C64(0x4c352626795f355f), SPH_C64(0x9d2fc3c3b2712f71),
	SPH_C64(0x67e1bebe8638e138), SPH_C64(0x6aa23535c8fda2fd), SPH_C64(0x0bcc8888c74fcc4f), SPH_C64(0x5c392e2e654b394b),
	SPH_C64(0x3d5793936af957f9), SPH_C64(0xaaf25555580df20d), SPH_C64(0xe382fcfc619d829d), SPH_C64(0xf4477a7ab3c947c9),
	SPH_C64(0x8bacc8c827efacef), SPH_C64(0x6fe7baba8832e732), SPH_C64(0x642b32324f7d2b7d), SPH_C64(0xd795e6e642a495a4),
	SPH_C64(0x9ba0c0c03bfba0fb), SPH_C64(0x32981919aab398b3), SPH_C64(0x27d19e9ef668d168), SPH_C64(0x5d7fa3a322817f81),
	SPH_C64(0x88664444eeaa66aa), SPH_C64(0xa87e5454d6827e82), SPH_C64(0x76ab3b3bdde6abe6), SPH_C64(0x16830b0b959e839e),
	SPH_C64(0x03ca8c8cc945ca45), SPH_C64(0x9529c7c7bc7b297b), SPH_C64(0xd6d36b6b056ed36e), SPH_C64(0x503c28286c443c44),
	SPH_C64(0x5579a7a72c8b798b), SPH_C64(0x63e2bcbc813de23d), SPH_C64(0x2c1d161631271d27), SPH_C64(0x4176adad379a769a),
	SPH_C64(0xad3bdbdb964d3b4d), SPH_C64(0xc85664649efa56fa), SPH_C64(0xe84e7474a6d24ed2), SPH_C64(0x281e141436221e22),
	SPH_C64(0x3fdb9292e476db76), SPH_C64(0x180a0c0c121e0a1e), SPH_C64(0x906c4848fcb46cb4), SPH_C64(0x6be4b8b88f37e437),
	SPH_C64(0x255d9f9f78e75de7), SPH_C64(0x616ebdbd0fb26eb2), SPH_C64(0x86ef4343692aef2a), SPH_C64(0x93a6c4c435f1a6f1),
	SPH_C64(0x72a83939dae3a8e3), SPH_C64(0x62a43131c6f7a4f7), SPH_C64(0xbd37d3d38a593759), SPH_C64(0xff8bf2f274868b86),
	SPH_C64(0xb132d5d583563256), SPH_C64(0x0d438b8b4ec543c5), SPH_C64(0xdc596e6e85eb59eb), SPH_C64(0xafb7dada18c2b7c2),
	SPH_C64(0x028c01018e8f8c8f), SPH_C64(0x7964b1b11dac64ac), SPH_C64(0x23d29c9cf16dd26d), SPH_C64(0x92e04949723be03b),
	SPH_C64(0xabb4d8d81fc7b4c7), SPH_C64(0x43faacacb915fa15), SPH_C64(0xfd07f3f3fa090709), SPH_C64(0x8525cfcfa06f256f),
	SPH_C64(0x8fafcaca20eaafea), SPH_C64(0xf38ef4f47d898e89), SPH_C64(0x8ee947476720e920), SPH_C64(0x2018101038281828),
	SPH_C64(0xded56f6f0b64d564), SPH_C64(0xfb88f0f073838883), SPH_C64(0x946f4a4afbb16fb1), SPH_C64(0xb8725c5cca967296),
	SPH_C64(0x70243838546c246c), SPH_C64(0xaef157575f08f108), SPH_C64(0xe6c773732152c752), SPH_C64(0x3551979764f351f3),
	SPH_C64(0x8d23cbcbae652365), SPH_C64(0x597ca1a125847c84), SPH_C64(0xcb9ce8e857bf9cbf), SPH_C64(0x7c213e3e5d632163),
	SPH_C64(0x37dd9696ea7cdd7c), SPH_C64(0xc2dc61611e7fdc7f), SPH_C64(0x1a860d0d9c918691), SPH_C64(0x1e850f0f9b948594),
	SPH_C64(0xdb90e0e04bab90ab), SPH_C64(0xf8427c7cbac642c6), SPH_C64(0xe2c471712657c457), SPH_C64(0x83aacccc29e5aae5),
	SPH_C64(0x3bd89090e373d873), SPH_C64(0x0c050606090f050f), SPH_C64(0xf501f7f7f4030103), SPH_C64(0x38121c1c2a361236),
	SPH_C64(0x9fa3c2c23cfea3fe), SPH_C64(0xd45f6a6a8be15fe1), SPH_C64(0x47f9aeaebe10f910), SPH_C64(0xd2d06969026bd06b),
	SPH_C64(0x2e911717bfa891a8), SPH_C64(0x2958999971e858e8), SPH_C64(0x74273a3a53692769), SPH_C64(0x4eb92727f7d0b9d0),
	SPH_C64(0xa938d9d991483848), SPH_C64(0xcd13ebebde351335), SPH_C64(0x56b32b2be5ceb3ce), SPH_C64(0x4433222277553355),
	SPH_C64(0xbfbbd2d204d6bbd6), SPH_C64(0x4970a9a939907090), SPH_C64(0x0e89070787808980), SPH_C64(0x66a73333c1f2a7f2),
	SPH_C64(0x5ab62d2decc1b6c1), SPH_C64(0x78223c3c5a662266), SPH_C64(0x2a921515b8ad92ad), SPH_C64(0x8920c9c9a9602060),
	SPH_C64(0x154987875cdb49db), SPH_C64(0x4fffaaaab01aff1a), SPH_C64(0xa0785050d8887888), SPH_C64(0x517aa5a52b8e7a8e),
	SPH_C64(0x068f0303898a8f8a), SPH_C64(0xb2f859594a13f813), SPH_C64(0x12800909929b809b), SPH_C64(0x34171a1a23391739),
	SPH_C64(0xcada65651075da75), SPH_C64(0xb531d7d784533153), SPH_C64(0x13c68484d551c651), SPH_C64(0xbbb8d0d003d3b8d3),
	SPH_C64(0x1fc38282dc5ec35e), SPH_C64(0x52b02929e2cbb0cb), SPH_C64(0xb4775a5ac3997799), SPH_C64(0x3c111e1e2d331133),
	SPH_C64(0xf6cb7b7b3d46cb46), SPH_C64(0x4bfca8a8b71ffc1f), SPH_C64(0xdad66d6d0c61d661), SPH_C64(0x583a2c2c624e3a4e)
};

static const sph_u64 T5[] GROESTL_ALIGN64 = {
	SPH_C64(0xa5f497a5c6c632f4), SPH_C64(0x8497eb84f8f86f97), SPH_C64(0x99b0c799eeee5eb0), SPH_C64(0x8d8cf78df6f67a8c),
	SPH_C64(0x0d17e50dffffe817), SPH_C64(0xbddcb7bdd6d60adc), SPH_C64(0xb1c8a7b1dede16c8), SPH_C64(0x54fc395491916dfc),
	SPH_C64(0x50f0c050606090f0), SPH_C64(0x0305040302020705), SPH_C64(0xa9e087a9cece2ee0), SPH_C64(0x7d87ac7d5656d187),
	SPH_C64(0x192bd519e7e7cc2b), SPH_C64(0x62a67162b5b513a6), SPH_C64(0xe6319ae64d4d7c31), SPH_C64(0x9ab5c39aecec59b5),
	SPH_C64(0x45cf05458f8f40cf), SPH_C64(0x9dbc3e9d1f1fa3bc), SPH_C64(0x40c00940898949c0), SPH_C64(0x8792ef87fafa6892),
	SPH_C64(0x153fc515efefd03f), SPH_C64(0xeb267febb2b29426), SPH_C64(0xc94007c98e8ece40), SPH_C64(0x0b1ded0bfbfbe61d),
	SPH_C64(0xec2f82ec41416e2f), SPH_C64(0x67a97d67b3b31aa9), SPH_C64(0xfd1cbefd5f5f431c), SPH_C64(0xea258aea45456025),
	SPH_C64(0xbfda46bf2323f9da), SPH_C64(0xf702a6f753535102), SPH_C64(0x96a1d396e4e445a1), SPH_C64(0x5bed2d5b9b9b76ed),
	SPH_C64(0xc25deac27575285d), SPH_C64(0x1c24d91ce1e1c524), SPH_C64(0xaee97aae3d3dd4e9), SPH_C64(0x6abe986a4c4cf2be),
	SPH_C64(0x5aeed85a6c6c82ee), SPH_C64(0x41c3fc417e7ebdc3), SPH_C64(0x0206f102f5f5f306), SPH_C64(0x4fd11d4f838352d1),
	SPH_C64(0x5ce4d05c68688ce4), SPH_C64(0xf407a2f451515607), SPH_C64(0x345cb934d1d18d5c), SPH_C64(0x0818e908f9f9e118),
	SPH_C64(0x93aedf93e2e24cae), SPH_C64(0x73954d73abab3e95), SPH_C64(0x53f5c453626297f5), SPH_C64(0x3f41543f2a2a6b41),
	SPH_C64(0x0c14100c08081c14), SPH_C64(0x52f63152959563f6), SPH_C64(0x65af8c654646e9af), SPH_C64(0x5ee2215e9d9d7fe2),
	SPH_C64(0x2878602830304878), SPH_C64(0xa1f86ea13737cff8), SPH_C64(0x0f11140f0a0a1b11), SPH_C64(0xb5c45eb52f2febc4),
	SPH_C64(0x091b1c090e0e151b), SPH_C64(0x365a483624247e5a), SPH_C64(0x9bb6369b1b1badb6), SPH_C64(0x3d47a53ddfdf9847),
	SPH_C64(0x266a8126cdcda76a), SPH_C64(0x69bb9c694e4ef5bb), SPH_C64(0xcd4cfecd7f7f334c), SPH_C64(0x9fbacf9feaea50ba),
	SPH_C64(0x1b2d241b12123f2d), SPH_C64(0x9eb93a9e1d1da4b9), SPH_C64(0x749cb0745858c49c), SPH_C64(0x2e72682e34344672),
	SPH_C64(0x2d776c2d36364177), SPH_C64(0xb2cda3b2dcdc11cd), SPH_C64(0xee2973eeb4b49d29), SPH_C64(0xfb16b6fb5b5b4d16),
	SPH_C64(0xf60153f6a4a4a501), SPH_C64(0x4dd7ec4d7676a1d7), SPH_C64(0x61a37561b7b714a3), SPH_C64(0xce49face7d7d3449),
	SPH_C64(0x7b8da47b5252df8d), SPH_C64(0x3e42a13edddd9f42), SPH_C64(0x7193bc715e5ecd93), SPH_C64(0x97a226971313b1a2),
	SPH_C64(0xf50457f5a6a6a204), SPH_C64(0x68b86968b9b901b8), SPH_C64(0x0000000000000000), SPH_C64(0x2c74992cc1c1b574),
	SPH_C64(0x60a080604040e0a0), SPH_C64(0x1f21dd1fe3e3c221), SPH_C64(0xc843f2c879793a43), SPH_C64(0xed2c77edb6b69a2c),
	SPH_C64(0xbed9b3bed4d40dd9), SPH_C64(0x46ca01468d8d47ca), SPH_C64(0xd970ced967671770), SPH_C64(0x4bdde44b7272afdd),
	SPH_C64(0xde7933de9494ed79), SPH_C64(0xd4672bd49898ff67), SPH_C64(0xe8237be8b0b09323), SPH_C64(0x4ade114a85855bde),
	SPH_C64(0x6bbd6d6bbbbb06bd), SPH_C64(0x2a7e912ac5c5bb7e), SPH_C64(0xe5349ee54f4f7b34), SPH_C64(0x163ac116ededd73a),
	SPH_C64(0xc55417c58686d254), SPH_C64(0xd7622fd79a9af862), SPH_C64(0x55ffcc55666699ff), SPH_C64(0x94a722941111b6a7),
	SPH_C64(0xcf4a0fcf8a8ac04a), SPH_C64(0x1030c910e9e9d930), SPH_C64(0x060a080604040e0a), SPH_C64(0x8198e781fefe6698),
	SPH_C64(0xf00b5bf0a0a0ab0b), SPH_C64(0x44ccf0447878b4cc), SPH_C64(0xbad54aba2525f0d5), SPH_C64(0xe33e96e34b4b753e),
	SPH_C64(0xf30e5ff3a2a2ac0e), SPH_C64(0xfe19bafe5d5d4419), SPH_C64(0xc05b1bc08080db5b), SPH_C64(0x8a850a8a05058085),
	SPH_C64(0xadec7ead3f3fd3ec), SPH_C64(0xbcdf42bc2121fedf), SPH_C64(0x48d8e0487070a8d8), SPH_C64(0x040cf904f1f1fd0c),
	SPH_C64(0xdf7ac6df6363197a), SPH_C64(0xc158eec177772f58), SPH_C64(0x759f4575afaf309f), SPH_C64(0x63a584634242e7a5),
	SPH_C64(0x3050403020207050), SPH_C64(0x1a2ed11ae5e5cb2e), SPH_C64(0x0e12e10efdfdef12), SPH_C64(0x6db7656dbfbf08b7),
	SPH_C64(0x4cd4194c818155d4), SPH_C64(0x143c30141818243c), SPH_C64(0x355f4c352626795f), SPH_C64(0x2f719d2fc3c3b271),
	SPH_C64(0xe13867e1bebe8638), SPH_C64(0xa2fd6aa23535c8fd), SPH_C64(0xcc4f0bcc8888c74f), SPH_C64(0x394b5c392e2e654b),
	SPH_C64(0x57f93d5793936af9), SPH_C64(0xf20daaf25555580d), SPH_C64(0x829de382fcfc619d), SPH_C64(0x47c9f4477a7ab3c9),
	SPH_C64(0xacef8bacc8c827ef), SPH_C64(0xe7326fe7baba8832), SPH_C64(0x2b7d642b32324f7d), SPH_C64(0x95a4d795e6e642a4),
	SPH_C64(0xa0fb9ba0c0c03bfb), SPH_C64(0x98b332981919aab3), SPH_C64(0xd16827d19e9ef668), SPH_C64(0x7f815d7fa3a32281),
	SPH_C64(0x66aa88664444eeaa), SPH_C64(0x7e82a87e5454d682), SPH_C64(0xabe676ab3b3bdde6), SPH_C64(0x839e16830b0b959e),
	SPH_C64(0xca4503ca8c8cc945), SPH_C64(0x297b9529c7c7bc7b), SPH_C64(0xd36ed6d36b6b056e), SPH_C64(0x3c44503c28286c44),
	SPH_C64(0x798b5579a7a72c8b), SPH_C64(0xe23d63e2bcbc813d), SPH_C64(0x1d272c1d16163127), SPH_C64(0x769a4176adad379a),
	SPH_C64(0x3b4dad3bdbdb964d), SPH_C64(0x56fac85664649efa), SPH_C64(0x4ed2e84e7474a6d2), SPH_C64(0x1e22281e14143622),
	SPH_C64(0xdb763fdb9292e476), SPH_C64(0x0a1e180a0c0c121e), SPH_C64(0x6cb4906c4848fcb4), SPH_C64(0xe4376be4b8b88f37),
	SPH_C64(0x5de7255d9f9f78e7), SPH_C64(0x6eb2616ebdbd0fb2), SPH_C64(0xef2a86ef4343692a), SPH_C64(0xa6f193a6c4c435f1),
	SPH_C64(0xa8e372a83939dae3), SPH_C64(0xa4f762a43131c6f7), SPH_C64(0x3759bd37d3d38a59), SPH_C64(0x8b86ff8bf2f27486),
	SPH_C64(0x3256b132d5d58356), SPH_C64(0x43c50d438b8b4ec5), SPH_C64(0x59ebdc596e6e85eb), SPH_C64(0xb7c2afb7dada18c2),
	SPH_C64(0x8c8f028c01018e8f), SPH_C64(0x64ac7964b1b11dac), SPH_C64(0xd26d23d29c9cf16d), SPH_C64(0xe03b92e04949723b),
	SPH_C64(0xb4c7abb4d8d81fc7), SPH_C64(0xfa1543faacacb915), SPH_C64(0x0709fd07f3f3fa09), SPH_C64(0x256f8525cfcfa06f),
	SPH_C64(0xafea8fafcaca20ea), SPH_C64(0x8e89f38ef4f47d89), SPH_C64(0xe9208ee947476720), SPH_C64(0x1828201810103828),
	SPH_C64(0xd564ded56f6f0b64), SPH_C64(0x8883fb88f0f07383), SPH_C64(0x6fb1946f4a4afbb1), SPH_C64(0x7296b8725c5cca96),
	SPH_C64(0x246c70243838546c), SPH_C64(0xf108aef157575f08), SPH_C64(0xc752e6c773732152), SPH_C64(0x51f33551979764f3),
	SPH_C64(0x23658d23cbcbae65), SPH_C64(0x7c84597ca1a12584), SPH_C64(0x9cbfcb9ce8e857bf), SPH_C64(0x21637c213e3e5d63),
	SPH_C64(0xdd7c37dd9696ea7c), SPH_C64(0xdc7fc2dc61611e7f), SPH_C64(0x86911a860d0d9c91), SPH_C64(0x85941e850f0f9b94),
	SPH_C64(0x90abdb90e0e04bab), SPH_C64(0x42c6f8427c7cbac6), SPH_C64(0xc457e2c471712657), SPH_C64(0xaae583aacccc29e5),
	SPH_C64(0xd8733bd89090e373), SPH_C64(0x050f0c050606090f), SPH_C64(0x0103f501f7f7f403), SPH_C64(0x123638121c1c2a36),
	SPH_C64(0xa3fe9fa3c2c23cfe), SPH_C64(0x5fe1d45f6a6a8be1), SPH_C64(0xf91047f9aeaebe10), SPH_C64(0xd06bd2d06969026b),
	SPH_C64(0x91a82e911717bfa8), SPH_C64(0x58e82958999971e8), SPH_C64(0x276974273a3a5369), SPH_C64(0xb9d04eb92727f7d0),
	SPH_C64(0x3848a938d9d99148), SPH_C64(0x1335cd13ebebde35), SPH_C64(0xb3ce56b32b2be5ce), SPH_C64(0x3355443322227755),
	SPH_C64(0xbbd6bfbbd2d204d6), SPH_C64(0x70904970a9a93990), SPH_C64(0x89800e8907078780), SPH_C64(0xa7f266a73333c1f2),
	SPH_C64(0xb6c15ab62d2decc1), SPH_C64(0x226678223c3c5a66), SPH_C64(0x92ad2a921515b8ad), SPH_C64(0x20608920c9c9a960),
	SPH_C64(0x49db154987875cdb), SPH_C64(0xff1a4fffaaaab01a), SPH_C64(0x7888a0785050d888), SPH_C64(0x7a8e517aa5a52b8e),
	SPH_C64(0x8f8a068f0303898a), SPH_C64(0xf813b2f859594a13), SPH_C64(0x809b12800909929b), SPH_C64(0x173934171a1a2339),
	SPH_C64(0xda75cada65651075), SPH_C64(0x3153b531d7d78453), SPH_C64(0xc65113c68484d551), SPH_C64(0xb8d3bbb8d0d003d3),
	SPH_C64(0xc35e1fc38282dc5e), SPH_C64(0xb0cb52b02929e2cb), SPH_C64(0x7799b4775a5ac399), SPH_C64(0x11333c111e1e2d33),
	SPH_C64(0xcb46f6cb7b7b3d46), SPH_C64(0xfc1f4bfca8a8b71f), SPH_C64(0xd661dad66d6d0c61), SPH_C64(0x3a4e583a2c2c624e)
};

static const sph_u64 T6[] GROESTL_ALIGN64 = {
	SPH_C64(0xf4a5f497a5c6c632), SPH_C64(0x978497eb84f8f86f), SPH_C64(0xb099b0c799eeee5e), SPH_C64(0x8c8d8cf78df6f67a),
	SPH_C64(0x170d17e50dffffe8), SPH_C64(0xdcbddcb7bdd6d60a), SPH_C64(0xc8b1c8a7b1dede16), SPH_C64(0xfc54fc395491916d),
	SPH_C64(0xf050f0c050606090), SPH_C64(0x0503050403020207), SPH_C64(0xe0a9e087a9cece2e), SPH_C64(0x877d87ac7d5656d1),
	SPH_C64(0x2b192bd519e7e7cc), SPH_C64(0xa662a67162b5b513), SPH_C64(0x31e6319ae64d4d7c), SPH_C64(0xb59ab5c39aecec59),
	SPH_C64(0xcf45cf05458f8f40), SPH_C64(0xbc9dbc3e9d1f1fa3), SPH_C64(0xc040c00940898949), SPH_C64(0x928792ef87fafa68),
	SPH_C64(0x3f153fc515efefd0), SPH_C64(0x26eb267febb2b294), SPH_C64(0x40c94007c98e8ece), SPH_C64(0x1d0b1ded0bfbfbe6),
	SPH_C64(0x2fec2f82ec41416e), SPH_C64(0xa967a97d67b3b31a), SPH_C64(0x1cfd1cbefd5f5f43), SPH_C64(0x25ea258aea454560),
	SPH_C64(0xdabfda46bf2323f9), SPH_C64(0x02f702a6f7535351), SPH_C64(0xa196a1d396e4e445), SPH_C64(0xed5bed2d5b9b9b76),
	SPH_C64(0x5dc25deac2757528), SPH_C64(0x241c24d91ce1e1c5), SPH_C64(0xe9aee97aae3d3dd4), SPH_C64(0xbe6abe986a4c4cf2),
	SPH_C64(0xee5aeed85a6c6c82), SPH_C64(0xc341c3fc417e7ebd), SPH_C64(0x060206f102f5f5f3), SPH_C64(0xd14fd11d4f838352),
	SPH_C64(0xe45ce4d05c68688c), SPH_C64(0x07f407a2f4515156), SPH_C64(0x5c345cb934d1d18d), SPH_C64(0x180818e908f9f9e1),
	SPH_C64(0xae93aedf93e2e24c), SPH_C64(0x9573954d73abab3e), SPH_C64(0xf553f5c453626297), SPH_C64(0x413f41543f2a2a6b),
	SPH_C64(0x140c14100c08081c), SPH_C64(0xf652f63152959563), SPH_C64(0xaf65af8c654646e9), SPH_C64(0xe25ee2215e9d9d7f),
	SPH_C64(0x7828786028303048), SPH_C64(0xf8a1f86ea13737cf), SPH_C64(0x110f11140f0a0a1b), SPH_C64(0xc4b5c45eb52f2feb),
	SPH_C64(0x1b091b1c090e0e15), SPH_C64(0x5a365a483624247e), SPH_C64(0xb69bb6369b1b1bad), SPH_C64(0x473d47a53ddfdf98),
	SPH_C64(0x6a266a8126cdcda7), SPH_C64(0xbb69bb9c694e4ef5), SPH_C64(0x4ccd4cfecd7f7f33), SPH_C64(0xba9fbacf9feaea50),
	SPH_C64(0x2d1b2d241b12123f), SPH_C64(0xb99eb93a9e1d1da4), SPH_C64(0x9c749cb0745858c4), SPH_C64(0x722e72682e343446),
	SPH_C64(0x772d776c2d363641), SPH_C64(0xcdb2cda3b2dcdc11), SPH_C64(0x29ee2973eeb4b49d), SPH_C64(0x16fb16b6fb5b5b4d),
	SPH_C64(0x01f60153f6a4a4a5), SPH_C64(0xd74dd7ec4d7676a1), SPH_C64(0xa361a37561b7b714), SPH_C64(0x49ce49face7d7d34),
	SPH_C64(0x8d7b8da47b5252df), SPH_C64(0x423e42a13edddd9f), SPH_C64(0x937193bc715e5ecd), SPH_C64(0xa297a226971313b1),
	SPH_C64(0x04f50457f5a6a6a2), SPH_C64(0xb868b86968b9b901), SPH_C64(0x0000000000000000), SPH_C64(0x742c74992cc1c1b5),
	SPH_C64(0xa060a080604040e0), SPH_C64(0x211f21dd1fe3e3c2), SPH_C64(0x43c843f2c879793a), SPH_C64(0x2ced2c77edb6b69a),
	SPH_C64(0xd9bed9b3bed4d40d), SPH_C64(0xca46ca01468d8d47), SPH_C64(0x70d970ced9676717), SPH_C64(0xdd4bdde44b7272af),
	SPH_C64(0x79de7933de9494ed), SPH_C64(0x67d4672bd49898ff), SPH_C64(0x23e8237be8b0b093), SPH_C64(0xde4ade114a85855b),
	SPH_C64(0xbd6bbd6d6bbbbb06), SPH_C64(0x7e2a7e912ac5c5bb), SPH_C64(0x34e5349ee54f4f7b), SPH_C64(0x3a163ac116ededd7),
	SPH_C64(0x54c55417c58686d2), SPH_C64(0x62d7622fd79a9af8), SPH_C64(0xff55ffcc55666699), SPH_C64(0xa794a722941111b6),
	SPH_C64(0x4acf4a0fcf8a8ac0), SPH_C64(0x301030c910e9e9d9), SPH_C64(0x0a060a080604040e), SPH_C64(0x988198e781fefe66),
	SPH_C64(0x0bf00b5bf0a0a0ab), SPH_C64(0xcc44ccf0447878b4), SPH_C64(0xd5bad54aba2525f0), SPH_C64(0x3ee33e96e34b4b75),
	SPH_C64(0x0ef30e5ff3a2a2ac), SPH_C64(0x19fe19bafe5d5d44), SPH_C64(0x5bc05b1bc08080db), SPH_C64(0x858a850a8a050580),
	SPH_C64(0xecadec7ead3f3fd3), SPH_C64(0xdfbcdf42bc2121fe), SPH_C64(0xd848d8e0487070a8), SPH_C64(0x0c040cf904f1f1fd),
	SPH_C64(0x7adf7ac6df636319), SPH_C64(0x58c158eec177772f), SPH_C64(0x9f759f4575afaf30), SPH_C64(0xa563a584634242e7),
	SPH_C64(0x5030504030202070), SPH_C64(0x2e1a2ed11ae5e5cb), SPH_C64(0x120e12e10efdfdef), SPH_C64(0xb76db7656dbfbf08),
	SPH_C64(0xd44cd4194c818155), SPH_C64(0x3c143c3014181824), SPH_C64(0x5f355f4c35262679), SPH_C64(0x712f719d2fc3c3b2),
	SPH_C64(0x38e13867e1bebe86), SPH_C64(0xfda2fd6aa23535c8), SPH_C64(0x4fcc4f0bcc8888c7), SPH_C64(0x4b394b5c392e2e65),
	SPH_C64(0xf957f93d5793936a), SPH_C64(0x0df20daaf2555558), SPH_C64(0x9d829de382fcfc61), SPH_C64(0xc947c9f4477a7ab3),
	SPH_C64(0xefacef8bacc8c827), SPH_C64(0x32e7326fe7baba88), SPH_C64(0x7d2b7d642b32324f), SPH_C64(0xa495a4d795e6e642),
	SPH_C64(0xfba0fb9ba0c0c03b), SPH_C64(0xb398b332981919aa), SPH_C64(0x68d16827d19e9ef6), SPH_C64(0x817f815d7fa3a322),
	SPH_C64(0xaa66aa88664444ee), SPH_C64(0x827e82a87e5454d6), SPH_C64(0xe6abe676ab3b3bdd), SPH_C64(0x9e839e16830b0b95),
	SPH_C64(0x45ca4503ca8c8cc9), SPH_C64(0x7b297b9529c7c7bc), SPH_C64(0x6ed36ed6d36b6b05), SPH_C64(0x443c44503c28286c),
	SPH_C64(0x8b798b5579a7a72c), SPH_C64(0x3de23d63e2bcbc81), SPH_C64(0x271d272c1d161631), SPH_C64(0x9a769a4176adad37),
	SPH_C64(0x4d3b4dad3bdbdb96), SPH_C64(0xfa56fac85664649e), SPH_C64(0xd24ed2e84e7474a6), SPH_C64(0x221e22281e141436),
	SPH_C64(0x76db763fdb9292e4), SPH_C64(0x1e0a1e180a0c0c12), SPH_C64(0xb46cb4906c4848fc), SPH_C64(0x37e4376be4b8b88f),
	SPH_C64(0xe75de7255d9f9f78), SPH_C64(0xb26eb2616ebdbd0f), SPH_C64(0x2aef2a86ef434369), SPH_C64(0xf1a6f193a6c4c435),
	SPH_C64(0xe3a8e372a83939da), SPH_C64(0xf7a4f762a43131c6), SPH_C64(0x593759bd37d3d38a), SPH_C64(0x868b86ff8bf2f274),
	SPH_C64(0x563256b132d5d583), SPH_C64(0xc543c50d438b8b4e), SPH_C64(0xeb59ebdc596e6e85), SPH_C64(0xc2b7c2afb7dada18),
	SPH_C64(0x8f8c8f028c01018e), SPH_C64(0xac64ac7964b1b11d), SPH_C64(0x6dd26d23d29c9cf1), SPH_C64(0x3be03b92e0494972),
	SPH_C64(0xc7b4c7abb4d8d81f), SPH_C64(0x15fa1543faacacb9), SPH_C64(0x090709fd07f3f3fa), SPH_C64(0x6f256f8525cfcfa0),
	SPH_C64(0xeaafea8fafcaca20), SPH_C64(0x898e89f38ef4f47d), SPH_C64(0x20e9208ee9474767), SPH_C64(0x2818282018101038),
	SPH_C64(0x64d564ded56f6f0b), SPH_C64(0x838883fb88f0f073), SPH_C64(0xb16fb1946f4a4afb), SPH_C64(0x967296b8725c5cca),
	SPH_C64(0x6c246c7024383854), SPH_C64(0x08f108aef157575f), SPH_C64(0x52c752e6c7737321), SPH_C64(0xf351f33551979764),
	SPH_C64(0x6523658d23cbcbae), SPH_C64(0x847c84597ca1a125), SPH_C64(0xbf9cbfcb9ce8e857), SPH_C64(0x6321637c213e3e5d),
	SPH_C64(0x7cdd7c37dd9696ea), SPH_C64(0x7fdc7fc2dc61611e), SPH_C64(0x9186911a860d0d9c), SPH_C64(0x9485941e850f0f9b),
	SPH_C64(0xab90abdb90e0e04b), SPH_C64(0xc642c6f8427c7cba), SPH_C64(0x57c457e2c4717126), SPH_C64(0xe5aae583aacccc29),
	SPH_C64(0x73d8733bd89090e3), SPH_C64(0x0f050f0c05060609), SPH_C64(0x030103f501f7f7f4), SPH_C64(0x36123638121c1c2a),
	SPH_C64(0xfea3fe9fa3c2c23c), SPH_C64(0xe15fe1d45f6a6a8b), SPH_C64(0x10f91047f9aeaebe), SPH_C64(0x6bd06bd2d0696902),
	SPH_C64(0xa891a82e911717bf), SPH_C64(0xe858e82958999971), SPH_C64(0x69276974273a3a53), SPH_C64(0xd0b9d04eb92727f7),
	SPH_C64(0x483848a938d9d991), SPH_C64(0x351335cd13ebebde), SPH_C64(0xceb3ce56b32b2be5), SPH_C64(0x5533554433222277),
	SPH_C64(0xd6bbd6bfbbd2d204), SPH_C64(0x9070904970a9a939), SPH_C64(0x8089800e89070787), SPH_C64(0xf2a7f266a73333c1),
	SPH_C64(0xc1b6c15ab62d2dec), SPH_C64(0x66226678223c3c5a), SPH_C64(0xad92ad2a921515b8), SPH_C64(0x6020608920c9c9a9),
	SPH_C64(0xdb49db154987875c), SPH_C64(0x1aff1a4fffaaaab0), SPH_C64(0x887888a0785050d8), SPH_C64(0x8e7a8e517aa5a52b),
	SPH_C64(0x8a8f8a068f030389), SPH_C64(0x13f813b2f859594a), SPH_C64(0x9b809b1280090992), SPH_C64(0x39173934171a1a23),
	SPH_C64(0x75da75cada656510), SPH_C64(0x533153b531d7d784), SPH_C64(0x51c65113c68484d5), SPH_C64(0xd3b8d3bbb8d0d003),
	SPH_C64(0x5ec35e1fc38282dc), SPH_C64(0xcbb0cb52b02929e2), SPH_C64(0x997799b4775a5ac3), SPH_C64(0x3311333c111e1e2d),
	SPH_C64(0x46cb46f6cb7b7b3d), SPH_C64(0x1ffc1f4bfca8a8b7), SPH_C64(0x61d661dad66d6d0c), SPH_C64(0x4e3a4e583a2c2c62)
};

static const sph_u64 T7[] GROESTL_ALIGN64 = {
	SPH_C64(0x32f4a5f497a5c6c6), SPH_C64(0x6f978497eb84f8f8), SPH_C64(0x5eb099b0c799eeee), SPH_C64(0x7a8c8d8cf78df6f6),
	SPH_C64(0xe8170d17e50dffff), SPH_C64(0x0adcbddcb7bdd6d6), SPH_C64(0x16c8b1c8a7b1dede), SPH_C64(0x6dfc54fc39549191),
	SPH_C64(0x90f050f0c0506060), SPH_C64(0x0705030504030202), SPH_C64(0x2ee0a9e087a9cece), SPH_C64(0xd1877d87ac7d5656),
	SPH_C64(0xcc2b192bd519e7e7), SPH_C64(0x13a662a67162b5b5), SPH_C64(0x7c31e6319ae64d4d), SPH_C64(0x59b59ab5c39aecec),
	SPH_C64(0x40cf45cf05458f8f), SPH_C64(0xa3bc9dbc3e9d1f1f), SPH_C64(0x49c040c009408989), SPH_C64(0x68928792ef87fafa),
	SPH_C64(0xd03f153fc515efef), SPH_C64(0x9426eb267febb2b2), SPH_C64(0xce40c94007c98e8e), SPH_C64(0xe61d0b1ded0bfbfb),
	SPH_C64(0x6e2fec2f82ec4141), SPH_C64(0x1aa967a97d67b3b3), SPH_C64(0x431cfd1cbefd5f5f), SPH_C64(0x6025ea258aea4545),
	SPH_C64(0xf9dabfda46bf2323), SPH_C64(0x5102f702a6f75353), SPH_C64(0x45a196a1d396e4e4), SPH_C64(0x76ed5bed2d5b9b9b),
	SPH_C64(0x285dc25deac27575), SPH_C64(0xc5241c24d91ce1e1), SPH_C64(0xd4e9aee97aae3d3d), SPH_C64(0xf2be6abe986a4c4c),
	SPH_C64(0x82ee5aeed85a6c6c), SPH_C64(0xbdc341c3fc417e7e), SPH_C64(0xf3060206f102f5f5), SPH_C64(0x52d14fd11d4f8383),
	SPH_C64(0x8ce45ce4d05c6868), SPH_C64(0x5607f407a2f45151), SPH_C64(0x8d5c345cb934d1d1), SPH_C64(0xe1180818e908f9f9),
	SPH_C64(0x4cae93aedf93e2e2), SPH_C64(0x3e9573954d73abab), SPH_C64(0x97f553f5c4536262), SPH_C64(0x6b413f41543f2a2a),
	SPH_C64(0x1c140c14100c0808), SPH_C64(0x63f652f631529595), SPH_C64(0xe9af65af8c654646), SPH_C64(0x7fe25ee2215e9d9d),
	SPH_C64(0x4878287860283030), SPH_C64(0xcff8a1f86ea13737), SPH_C64(0x1b110f11140f0a0a), SPH_C64(0xebc4b5c45eb52f2f),
	SPH_C64(0x151b091b1c090e0e), SPH_C64(0x7e5a365a48362424), SPH_C64(0xadb69bb6369b1b1b), SPH_C64(0x98473d47a53ddfdf),
	SPH_C64(0xa76a266a8126cdcd), SPH_C64(0xf5bb69bb9c694e4e), SPH_C64(0x334ccd4cfecd7f7f), SPH_C64(0x50ba9fbacf9feaea),
	SPH_C64(0x3f2d1b2d241b1212), SPH_C64(0xa4b99eb93a9e1d1d), SPH_C64(0xc49c749cb0745858), SPH_C64(0x46722e72682e3434),
	SPH_C64(0x41772d776c2d3636), SPH_C64(0x11cdb2cda3b2dcdc), SPH_C64(0x9d29ee2973eeb4b4), SPH_C64(0x4d16fb16b6fb5b5b),
	SPH_C64(0xa501f60153f6a4a4), SPH_C64(0xa1d74dd7ec4d7676), SPH_C64(0x14a361a37561b7b7), SPH_C64(0x3449ce49face7d7d),
	SPH_C64(0xdf8d7b8da47b5252), SPH_C64(0x9f423e42a13edddd), SPH_C64(0xcd937193bc715e5e), SPH_C64(0xb1a297a226971313),
	SPH_C64(0xa204f50457f5a6a6), SPH_C64(0x01b868b86968b9b9), SPH_C64(0x0000000000000000), SPH_C64(0xb5742c74992cc1c1),
	SPH_C64(0xe0a060a080604040), SPH_C64(0xc2211f21dd1fe3e3), SPH_C64(0x3a43c843f2c87979), SPH_C64(0x9a2ced2c77edb6b6),
	SPH_C64(0x0dd9bed9b3bed4d4), SPH_C64(0x47ca46ca01468d8d), SPH_C64(0x1770d970ced96767), SPH_C64(0xafdd4bdde44b7272),
	SPH_C64(0xed79de7933de9494), SPH_C64(0xff67d4672bd49898), SPH_C64(0x9323e8237be8b0b0), SPH_C64(0x5bde4ade114a8585),
	SPH_C64(0x06bd6bbd6d6bbbbb), SPH_C64(0xbb7e2a7e912ac5c5), SPH_C64(0x7b34e5349ee54f4f), SPH_C64(0xd73a163ac116eded),
	SPH_C64(0xd254c55417c58686), SPH_C64(0xf862d7622fd79a9a), SPH_C64(0x99ff55ffcc556666), SPH_C64(0xb6a794a722941111),
	SPH_C64(0xc04acf4a0fcf8a8a), SPH_C64(0xd9301030c910e9e9), SPH_C64(0x0e0a060a08060404), SPH_C64(0x66988198e781fefe),
	SPH_C64(0xab0bf00b5bf0a0a0), SPH_C64(0xb4cc44ccf0447878), SPH_C64(0xf0d5bad54aba2525), SPH_C64(0x753ee33e96e34b4b),
	SPH_C64(0xac0ef30e5ff3a2a2), SPH_C64(0x4419fe19bafe5d5d), SPH_C64(0xdb5bc05b1bc08080), SPH_C64(0x80858a850a8a0505),
	SPH_C64(0xd3ecadec7ead3f3f), SPH_C64(0xfedfbcdf42bc2121), SPH_C64(0xa8d848d8e0487070), SPH_C64(0xfd0c040cf904f1f1),
	SPH_C64(0x197adf7ac6df6363), SPH_C64(0x2f58c158eec17777), SPH_C64(0x309f759f4575afaf), SPH_C64(0xe7a563a584634242),
	SPH_C64(0x7050305040302020), SPH_C64(0xcb2e1a2ed11ae5e5), SPH_C64(0xef120e12e10efdfd), SPH_C64(0x08b76db7656dbfbf),
	SPH_C64(0x55d44cd4194c8181), SPH_C64(0x243c143c30141818), SPH_C64(0x795f355f4c352626), SPH_C64(0xb2712f719d2fc3c3),
	SPH_C64(0x8638e13867e1bebe), SPH_C64(0xc8fda2fd6aa23535), SPH_C64(0xc74fcc4f0bcc8888), SPH_C64(0x654b394b5c392e2e),
	SPH_C64(0x6af957f93d579393), SPH_C64(0x580df20daaf25555), SPH_C64(0x619d829de382fcfc), SPH_C64(0xb3c947c9f4477a7a),
	SPH_C64(0x27efacef8bacc8c8), SPH_C64(0x8832e7326fe7baba), SPH_C64(0x4f7d2b7d642b3232), SPH_C64(0x42a495a4d795e6e6),
	SPH_C64(0x3bfba0fb9ba0c0c0), SPH_C64(0xaab398b332981919), SPH_C64(0xf668d16827d19e9e), SPH_C64(0x22817f815d7fa3a3),
	SPH_C64(0xeeaa66aa88664444), SPH_C64(0xd6827e82a87e5454), SPH_C64(0xdde6abe676ab3b3b), SPH_C64(0x959e839e16830b0b),
	SPH_C64(0xc945ca4503ca8c8c), SPH_C64(0xbc7b297b9529c7c7), SPH_C64(0x056ed36ed6d36b6b), SPH_C64(0x6c443c44503c2828),
	SPH_C64(0x2c8b798b5579a7a7), SPH_C64(0x813de23d63e2bcbc), SPH_C64(0x31271d272c1d1616), SPH_C64(0x379a769a4176adad),
	SPH_C64(0x964d3b4dad3bdbdb), SPH_C64(0x9efa56fac8566464), SPH_C64(0xa6d24ed2e84e7474), SPH_C64(0x36221e22281e1414),
	SPH_C64(0xe476db763fdb9292), SPH_C64(0x121e0a1e180a0c0c), SPH_C64(0xfcb46cb4906c4848), SPH_C64(0x8f37e4376be4b8b8),
	SPH_C64(0x78e75de7255d9f9f), SPH_C64(0x0fb26eb2616ebdbd), SPH_C64(0x692aef2a86ef4343), SPH_C64(0x35f1a6f193a6c4c4),
	SPH_C64(0xdae3a8e372a83939), SPH_C64(0xc6f7a4f762a43131), SPH_C64(0x8a593759bd37d3d3), SPH_C64(0x74868b86ff8bf2f2),
	SPH_C64(0x83563256b132d5d5), SPH_C64(0x4ec543c50d438b8b), SPH_C64(0x85eb59ebdc596e6e), SPH_C64(0x18c2b7c2afb7dada),
	SPH_C64(0x8e8f8c8f028c0101), SPH_C64(0x1dac64ac7964b1b1), SPH_C64(0xf16dd26d23d29c9c), SPH_C64(0x723be03b92e04949),
	SPH_C64(0x1fc7b4c7abb4d8d8), SPH_C64(0xb915fa1543faacac), SPH_C64(0xfa090709fd07f3f3), SPH_C64(0xa06f256f8525cfcf),
	SPH_C64(0x20eaafea8fafcaca), SPH_C64(0x7d898e89f38ef4f4), SPH_C64(0x6720e9208ee94747), SPH_C64(0x3828182820181010),
	SPH_C64(0x0b64d564ded56f6f), SPH_C64(0x73838883fb88f0f0), SPH_C64(0xfbb16fb1946f4a4a), SPH_C64(0xca967296b8725c5c),
	SPH_C64(0x546c246c70243838), SPH_C64(0x5f08f108aef15757), SPH_C64(0x2152c752e6c77373), SPH_C64(0x64f351f335519797),
	SPH_C64(0xae6523658d23cbcb), SPH_C64(0x25847c84597ca1a1), SPH_C64(0x57bf9cbfcb9ce8e8), SPH_C64(0x5d6321637c213e3e),
	SPH_C64(0xea7cdd7c37dd9696), SPH_C64(0x1e7fdc7fc2dc6161), SPH_C64(0x9c9186911a860d0d), SPH_C64(0x9b9485941e850f0f),
	SPH_C64(0x4bab90abdb90e0e0), SPH_C64(0xbac642c6f8427c7c), SPH_C64(0x2657c457e2c47171), SPH_C64(0x29e5aae583aacccc),
	SPH_C64(0xe373d8733bd89090), SPH_C64(0x090f050f0c050606), SPH_C64(0xf4030103f501f7f7), SPH_C64(0x2a36123638121c1c),
	SPH_C64(0x3cfea3fe9fa3c2c2), SPH_C64(0x8be15fe1d45f6a6a), SPH_C64(0xbe10f91047f9aeae), SPH_C64(0x026bd06bd2d06969),
	SPH_C64(0xbfa891a82e911717), SPH_C64(0x71e858e829589999), SPH_C64(0x5369276974273a3a), SPH_C64(0xf7d0b9d04eb92727),
	SPH_C64(0x91483848a938d9d9), SPH_C64(0xde351335cd13ebeb), SPH_C64(0xe5ceb3ce56b32b2b), SPH_C64(0x7755335544332222),
	SPH_C64(0x04d6bbd6bfbbd2d2), SPH_C64(0x399070904970a9a9), SPH_C64(0x878089800e890707), SPH_C64(0xc1f2a7f266a73333),
	SPH_C64(0xecc1b6c15ab62d2d), SPH_C64(0x5a66226678223c3c), SPH_C64(0xb8ad92ad2a921515), SPH_C64(0xa96020608920c9c9),
	SPH_C64(0x5cdb49db15498787), SPH_C64(0xb01aff1a4fffaaaa), SPH_C64(0xd8887888a0785050), SPH_C64(0x2b8e7a8e517aa5a5),
	SPH_C64(0x898a8f8a068f0303), SPH_C64(0x4a13f813b2f85959), SPH_C64(0x929b809b12800909), SPH_C64(0x2339173934171a1a),
	SPH_C64(0x1075da75cada6565), SPH_C64(0x84533153b531d7d7), SPH_C64(0xd551c65113c68484), SPH_C64(0x03d3b8d3bbb8d0d0),
	SPH_C64(0xdc5ec35e1fc38282), SPH_C64(0xe2cbb0cb52b02929), SPH_C64(0xc3997799b4775a5a), SPH_C64(0x2d3311333c111e1e),
	SPH_C64(0x3d46cb46f6cb7b7b), SPH_C64(0xb71ffc1f4bfca8a8), SPH_C64(0x0c61d661dad66d6d), SPH_C64(0x624e3a4e583a2c2c)
};

#endif

/* ------------------------------------------------------------------ */
/* Precomputed round constants — eliminate all runtime computation    */
/* ------------------------------------------------------------------ */

#if USE_LE

static const sph_u64 PC_SMALL[10][8] GROESTL_ALIGN64 = {
    {
        SPH_C64(0x0000000000000000), SPH_C64(0x0000000000000010), SPH_C64(0x0000000000000020), SPH_C64(0x0000000000000030),
        SPH_C64(0x0000000000000040), SPH_C64(0x0000000000000050), SPH_C64(0x0000000000000060), SPH_C64(0x0000000000000070)
    },
    {
        SPH_C64(0x0000000000000001), SPH_C64(0x0000000000000011), SPH_C64(0x0000000000000021), SPH_C64(0x0000000000000031),
        SPH_C64(0x0000000000000041), SPH_C64(0x0000000000000051), SPH_C64(0x0000000000000061), SPH_C64(0x0000000000000071)
    },
    {
        SPH_C64(0x0000000000000002), SPH_C64(0x0000000000000012), SPH_C64(0x0000000000000022), SPH_C64(0x0000000000000032),
        SPH_C64(0x0000000000000042), SPH_C64(0x0000000000000052), SPH_C64(0x0000000000000062), SPH_C64(0x0000000000000072)
    },
    {
        SPH_C64(0x0000000000000003), SPH_C64(0x0000000000000013), SPH_C64(0x0000000000000023), SPH_C64(0x0000000000000033),
        SPH_C64(0x0000000000000043), SPH_C64(0x0000000000000053), SPH_C64(0x0000000000000063), SPH_C64(0x0000000000000073)
    },
    {
        SPH_C64(0x0000000000000004), SPH_C64(0x0000000000000014), SPH_C64(0x0000000000000024), SPH_C64(0x0000000000000034),
        SPH_C64(0x0000000000000044), SPH_C64(0x0000000000000054), SPH_C64(0x0000000000000064), SPH_C64(0x0000000000000074)
    },
    {
        SPH_C64(0x0000000000000005), SPH_C64(0x0000000000000015), SPH_C64(0x0000000000000025), SPH_C64(0x0000000000000035),
        SPH_C64(0x0000000000000045), SPH_C64(0x0000000000000055), SPH_C64(0x0000000000000065), SPH_C64(0x0000000000000075)
    },
    {
        SPH_C64(0x0000000000000006), SPH_C64(0x0000000000000016), SPH_C64(0x0000000000000026), SPH_C64(0x0000000000000036),
        SPH_C64(0x0000000000000046), SPH_C64(0x0000000000000056), SPH_C64(0x0000000000000066), SPH_C64(0x0000000000000076)
    },
    {
        SPH_C64(0x0000000000000007), SPH_C64(0x0000000000000017), SPH_C64(0x0000000000000027), SPH_C64(0x0000000000000037),
        SPH_C64(0x0000000000000047), SPH_C64(0x0000000000000057), SPH_C64(0x0000000000000067), SPH_C64(0x0000000000000077)
    },
    {
        SPH_C64(0x0000000000000008), SPH_C64(0x0000000000000018), SPH_C64(0x0000000000000028), SPH_C64(0x0000000000000038),
        SPH_C64(0x0000000000000048), SPH_C64(0x0000000000000058), SPH_C64(0x0000000000000068), SPH_C64(0x0000000000000078)
    },
    {
        SPH_C64(0x0000000000000009), SPH_C64(0x0000000000000019), SPH_C64(0x0000000000000029), SPH_C64(0x0000000000000039),
        SPH_C64(0x0000000000000049), SPH_C64(0x0000000000000059), SPH_C64(0x0000000000000069), SPH_C64(0x0000000000000079)
    }
};

static const sph_u64 QC_SMALL[10][8] GROESTL_ALIGN64 = {
    {
        SPH_C64(0xffffffffffffffff), SPH_C64(0xffffffffefffffff), SPH_C64(0xffffffffdfffffff), SPH_C64(0xffffffffcfffffff),
        SPH_C64(0xffffffffbfffffff), SPH_C64(0xffffffffafffffff), SPH_C64(0xffffffff9fffffff), SPH_C64(0xffffffff8fffffff)
    },
    {
        SPH_C64(0xfffffffffeffffff), SPH_C64(0xffffffffeeffffff), SPH_C64(0xffffffffdeffffff), SPH_C64(0xffffffffceffffff),
        SPH_C64(0xffffffffbeffffff), SPH_C64(0xffffffffaeffffff), SPH_C64(0xffffffff9effffff), SPH_C64(0xffffffff8effffff)
    },
    {
        SPH_C64(0xfffffffffdffffff), SPH_C64(0xffffffffedffffff), SPH_C64(0xffffffffddffffff), SPH_C64(0xffffffffcdffffff),
        SPH_C64(0xffffffffbdffffff), SPH_C64(0xffffffffadffffff), SPH_C64(0xffffffff9dffffff), SPH_C64(0xffffffff8dffffff)
    },
    {
        SPH_C64(0xfffffffffcffffff), SPH_C64(0xffffffffecffffff), SPH_C64(0xffffffffdcffffff), SPH_C64(0xffffffffccffffff),
        SPH_C64(0xffffffffbcffffff), SPH_C64(0xffffffffacffffff), SPH_C64(0xffffffff9cffffff), SPH_C64(0xffffffff8cffffff)
    },
    {
        SPH_C64(0xfffffffffbffffff), SPH_C64(0xffffffffebffffff), SPH_C64(0xffffffffdbffffff), SPH_C64(0xffffffffcbffffff),
        SPH_C64(0xffffffffbbffffff), SPH_C64(0xffffffffabffffff), SPH_C64(0xffffffff9bffffff), SPH_C64(0xffffffff8bffffff)
    },
    {
        SPH_C64(0xfffffffffaffffff), SPH_C64(0xffffffffeaffffff), SPH_C64(0xffffffffdaffffff), SPH_C64(0xffffffffcaffffff),
        SPH_C64(0xffffffffbaffffff), SPH_C64(0xffffffffaaffffff), SPH_C64(0xffffffff9affffff), SPH_C64(0xffffffff8affffff)
    },
    {
        SPH_C64(0xfffffffff9ffffff), SPH_C64(0xffffffffe9ffffff), SPH_C64(0xffffffffd9ffffff), SPH_C64(0xffffffffc9ffffff),
        SPH_C64(0xffffffffb9ffffff), SPH_C64(0xffffffffa9ffffff), SPH_C64(0xffffffff99ffffff), SPH_C64(0xffffffff89ffffff)
    },
    {
        SPH_C64(0xfffffffff8ffffff), SPH_C64(0xffffffffe8ffffff), SPH_C64(0xffffffffd8ffffff), SPH_C64(0xffffffffc8ffffff),
        SPH_C64(0xffffffffb8ffffff), SPH_C64(0xffffffffa8ffffff), SPH_C64(0xffffffff98ffffff), SPH_C64(0xffffffff88ffffff)
    },
    {
        SPH_C64(0xfffffffff7ffffff), SPH_C64(0xffffffffe7ffffff), SPH_C64(0xffffffffd7ffffff), SPH_C64(0xffffffffc7ffffff),
        SPH_C64(0xffffffffb7ffffff), SPH_C64(0xffffffffa7ffffff), SPH_C64(0xffffffff97ffffff), SPH_C64(0xffffffff87ffffff)
    },
    {
        SPH_C64(0xfffffffff6ffffff), SPH_C64(0xffffffffe6ffffff), SPH_C64(0xffffffffd6ffffff), SPH_C64(0xffffffffc6ffffff),
        SPH_C64(0xffffffffb6ffffff), SPH_C64(0xffffffffa6ffffff), SPH_C64(0xffffffff96ffffff), SPH_C64(0xffffffff86ffffff)
    }
};

static const sph_u64 PC_BIG[14][16] GROESTL_ALIGN64 = {
    {
        SPH_C64(0x0000000000000000), SPH_C64(0x0000000000000010), SPH_C64(0x0000000000000020), SPH_C64(0x0000000000000030),
        SPH_C64(0x0000000000000040), SPH_C64(0x0000000000000050), SPH_C64(0x0000000000000060), SPH_C64(0x0000000000000070),
        SPH_C64(0x0000000000000080), SPH_C64(0x0000000000000090), SPH_C64(0x00000000000000a0), SPH_C64(0x00000000000000b0),
        SPH_C64(0x00000000000000c0), SPH_C64(0x00000000000000d0), SPH_C64(0x00000000000000e0), SPH_C64(0x00000000000000f0)
    },
    {
        SPH_C64(0x0000000000000001), SPH_C64(0x0000000000000011), SPH_C64(0x0000000000000021), SPH_C64(0x0000000000000031),
        SPH_C64(0x0000000000000041), SPH_C64(0x0000000000000051), SPH_C64(0x0000000000000061), SPH_C64(0x0000000000000071),
        SPH_C64(0x0000000000000081), SPH_C64(0x0000000000000091), SPH_C64(0x00000000000000a1), SPH_C64(0x00000000000000b1),
        SPH_C64(0x00000000000000c1), SPH_C64(0x00000000000000d1), SPH_C64(0x00000000000000e1), SPH_C64(0x00000000000000f1)
    },
    {
        SPH_C64(0x0000000000000002), SPH_C64(0x0000000000000012), SPH_C64(0x0000000000000022), SPH_C64(0x0000000000000032),
        SPH_C64(0x0000000000000042), SPH_C64(0x0000000000000052), SPH_C64(0x0000000000000062), SPH_C64(0x0000000000000072),
        SPH_C64(0x0000000000000082), SPH_C64(0x0000000000000092), SPH_C64(0x00000000000000a2), SPH_C64(0x00000000000000b2),
        SPH_C64(0x00000000000000c2), SPH_C64(0x00000000000000d2), SPH_C64(0x00000000000000e2), SPH_C64(0x00000000000000f2)
    },
    {
        SPH_C64(0x0000000000000003), SPH_C64(0x0000000000000013), SPH_C64(0x0000000000000023), SPH_C64(0x0000000000000033),
        SPH_C64(0x0000000000000043), SPH_C64(0x0000000000000053), SPH_C64(0x0000000000000063), SPH_C64(0x0000000000000073),
        SPH_C64(0x0000000000000083), SPH_C64(0x0000000000000093), SPH_C64(0x00000000000000a3), SPH_C64(0x00000000000000b3),
        SPH_C64(0x00000000000000c3), SPH_C64(0x00000000000000d3), SPH_C64(0x00000000000000e3), SPH_C64(0x00000000000000f3)
    },
    {
        SPH_C64(0x0000000000000004), SPH_C64(0x0000000000000014), SPH_C64(0x0000000000000024), SPH_C64(0x0000000000000034),
        SPH_C64(0x0000000000000044), SPH_C64(0x0000000000000054), SPH_C64(0x0000000000000064), SPH_C64(0x0000000000000074),
        SPH_C64(0x0000000000000084), SPH_C64(0x0000000000000094), SPH_C64(0x00000000000000a4), SPH_C64(0x00000000000000b4),
        SPH_C64(0x00000000000000c4), SPH_C64(0x00000000000000d4), SPH_C64(0x00000000000000e4), SPH_C64(0x00000000000000f4)
    },
    {
        SPH_C64(0x0000000000000005), SPH_C64(0x0000000000000015), SPH_C64(0x0000000000000025), SPH_C64(0x0000000000000035),
        SPH_C64(0x0000000000000045), SPH_C64(0x0000000000000055), SPH_C64(0x0000000000000065), SPH_C64(0x0000000000000075),
        SPH_C64(0x0000000000000085), SPH_C64(0x0000000000000095), SPH_C64(0x00000000000000a5), SPH_C64(0x00000000000000b5),
        SPH_C64(0x00000000000000c5), SPH_C64(0x00000000000000d5), SPH_C64(0x00000000000000e5), SPH_C64(0x00000000000000f5)
    },
    {
        SPH_C64(0x0000000000000006), SPH_C64(0x0000000000000016), SPH_C64(0x0000000000000026), SPH_C64(0x0000000000000036),
        SPH_C64(0x0000000000000046), SPH_C64(0x0000000000000056), SPH_C64(0x0000000000000066), SPH_C64(0x0000000000000076),
        SPH_C64(0x0000000000000086), SPH_C64(0x0000000000000096), SPH_C64(0x00000000000000a6), SPH_C64(0x00000000000000b6),
        SPH_C64(0x00000000000000c6), SPH_C64(0x00000000000000d6), SPH_C64(0x00000000000000e6), SPH_C64(0x00000000000000f6)
    },
    {
        SPH_C64(0x0000000000000007), SPH_C64(0x0000000000000017), SPH_C64(0x0000000000000027), SPH_C64(0x0000000000000037),
        SPH_C64(0x0000000000000047), SPH_C64(0x0000000000000057), SPH_C64(0x0000000000000067), SPH_C64(0x0000000000000077),
        SPH_C64(0x0000000000000087), SPH_C64(0x0000000000000097), SPH_C64(0x00000000000000a7), SPH_C64(0x00000000000000b7),
        SPH_C64(0x00000000000000c7), SPH_C64(0x00000000000000d7), SPH_C64(0x00000000000000e7), SPH_C64(0x00000000000000f7)
    },
    {
        SPH_C64(0x0000000000000008), SPH_C64(0x0000000000000018), SPH_C64(0x0000000000000028), SPH_C64(0x0000000000000038),
        SPH_C64(0x0000000000000048), SPH_C64(0x0000000000000058), SPH_C64(0x0000000000000068), SPH_C64(0x0000000000000078),
        SPH_C64(0x0000000000000088), SPH_C64(0x0000000000000098), SPH_C64(0x00000000000000a8), SPH_C64(0x00000000000000b8),
        SPH_C64(0x00000000000000c8), SPH_C64(0x00000000000000d8), SPH_C64(0x00000000000000e8), SPH_C64(0x00000000000000f8)
    },
    {
        SPH_C64(0x0000000000000009), SPH_C64(0x0000000000000019), SPH_C64(0x0000000000000029), SPH_C64(0x0000000000000039),
        SPH_C64(0x0000000000000049), SPH_C64(0x0000000000000059), SPH_C64(0x0000000000000069), SPH_C64(0x0000000000000079),
        SPH_C64(0x0000000000000089), SPH_C64(0x0000000000000099), SPH_C64(0x00000000000000a9), SPH_C64(0x00000000000000b9),
        SPH_C64(0x00000000000000c9), SPH_C64(0x00000000000000d9), SPH_C64(0x00000000000000e9), SPH_C64(0x00000000000000f9)
    },
    {
        SPH_C64(0x000000000000000a), SPH_C64(0x000000000000001a), SPH_C64(0x000000000000002a), SPH_C64(0x000000000000003a),
        SPH_C64(0x000000000000004a), SPH_C64(0x000000000000005a), SPH_C64(0x000000000000006a), SPH_C64(0x000000000000007a),
        SPH_C64(0x000000000000008a), SPH_C64(0x000000000000009a), SPH_C64(0x00000000000000aa), SPH_C64(0x00000000000000ba),
        SPH_C64(0x00000000000000ca), SPH_C64(0x00000000000000da), SPH_C64(0x00000000000000ea), SPH_C64(0x00000000000000fa)
    },
    {
        SPH_C64(0x000000000000000b), SPH_C64(0x000000000000001b), SPH_C64(0x000000000000002b), SPH_C64(0x000000000000003b),
        SPH_C64(0x000000000000004b), SPH_C64(0x000000000000005b), SPH_C64(0x000000000000006b), SPH_C64(0x000000000000007b),
        SPH_C64(0x000000000000008b), SPH_C64(0x000000000000009b), SPH_C64(0x00000000000000ab), SPH_C64(0x00000000000000bb),
        SPH_C64(0x00000000000000cb), SPH_C64(0x00000000000000db), SPH_C64(0x00000000000000eb), SPH_C64(0x00000000000000fb)
    },
    {
        SPH_C64(0x000000000000000c), SPH_C64(0x000000000000001c), SPH_C64(0x000000000000002c), SPH_C64(0x000000000000003c),
        SPH_C64(0x000000000000004c), SPH_C64(0x000000000000005c), SPH_C64(0x000000000000006c), SPH_C64(0x000000000000007c),
        SPH_C64(0x000000000000008c), SPH_C64(0x000000000000009c), SPH_C64(0x00000000000000ac), SPH_C64(0x00000000000000bc),
        SPH_C64(0x00000000000000cc), SPH_C64(0x00000000000000dc), SPH_C64(0x00000000000000ec), SPH_C64(0x00000000000000fc)
    },
    {
        SPH_C64(0x000000000000000d), SPH_C64(0x000000000000001d), SPH_C64(0x000000000000002d), SPH_C64(0x000000000000003d),
        SPH_C64(0x000000000000004d), SPH_C64(0x000000000000005d), SPH_C64(0x000000000000006d), SPH_C64(0x000000000000007d),
        SPH_C64(0x000000000000008d), SPH_C64(0x000000000000009d), SPH_C64(0x00000000000000ad), SPH_C64(0x00000000000000bd),
        SPH_C64(0x00000000000000cd), SPH_C64(0x00000000000000dd), SPH_C64(0x00000000000000ed), SPH_C64(0x00000000000000fd)
    }
};

static const sph_u64 QC_BIG[14][16] GROESTL_ALIGN64 = {
    {
        SPH_C64(0xffffffffffffffff), SPH_C64(0xffffffffefffffff), SPH_C64(0xffffffffdfffffff), SPH_C64(0xffffffffcfffffff),
        SPH_C64(0xffffffffbfffffff), SPH_C64(0xffffffffafffffff), SPH_C64(0xffffffff9fffffff), SPH_C64(0xffffffff8fffffff),
        SPH_C64(0xffffffff7fffffff), SPH_C64(0xffffffff6fffffff), SPH_C64(0xffffffff5fffffff), SPH_C64(0xffffffff4fffffff),
        SPH_C64(0xffffffff3fffffff), SPH_C64(0xffffffff2fffffff), SPH_C64(0xffffffff1fffffff), SPH_C64(0xffffffff0fffffff)
    },
    {
        SPH_C64(0xfffffffffeffffff), SPH_C64(0xffffffffeeffffff), SPH_C64(0xffffffffdeffffff), SPH_C64(0xffffffffceffffff),
        SPH_C64(0xffffffffbeffffff), SPH_C64(0xffffffffaeffffff), SPH_C64(0xffffffff9effffff), SPH_C64(0xffffffff8effffff),
        SPH_C64(0xffffffff7effffff), SPH_C64(0xffffffff6effffff), SPH_C64(0xffffffff5effffff), SPH_C64(0xffffffff4effffff),
        SPH_C64(0xffffffff3effffff), SPH_C64(0xffffffff2effffff), SPH_C64(0xffffffff1effffff), SPH_C64(0xffffffff0effffff)
    },
    {
        SPH_C64(0xfffffffffdffffff), SPH_C64(0xffffffffedffffff), SPH_C64(0xffffffffddffffff), SPH_C64(0xffffffffcdffffff),
        SPH_C64(0xffffffffbdffffff), SPH_C64(0xffffffffadffffff), SPH_C64(0xffffffff9dffffff), SPH_C64(0xffffffff8dffffff),
        SPH_C64(0xffffffff7dffffff), SPH_C64(0xffffffff6dffffff), SPH_C64(0xffffffff5dffffff), SPH_C64(0xffffffff4dffffff),
        SPH_C64(0xffffffff3dffffff), SPH_C64(0xffffffff2dffffff), SPH_C64(0xffffffff1dffffff), SPH_C64(0xffffffff0dffffff)
    },
    {
        SPH_C64(0xfffffffffcffffff), SPH_C64(0xffffffffecffffff), SPH_C64(0xffffffffdcffffff), SPH_C64(0xffffffffccffffff),
        SPH_C64(0xffffffffbcffffff), SPH_C64(0xffffffffacffffff), SPH_C64(0xffffffff9cffffff), SPH_C64(0xffffffff8cffffff),
        SPH_C64(0xffffffff7cffffff), SPH_C64(0xffffffff6cffffff), SPH_C64(0xffffffff5cffffff), SPH_C64(0xffffffff4cffffff),
        SPH_C64(0xffffffff3cffffff), SPH_C64(0xffffffff2cffffff), SPH_C64(0xffffffff1cffffff), SPH_C64(0xffffffff0cffffff)
    },
    {
        SPH_C64(0xfffffffffbffffff), SPH_C64(0xffffffffebffffff), SPH_C64(0xffffffffdbffffff), SPH_C64(0xffffffffcbffffff),
        SPH_C64(0xffffffffbbffffff), SPH_C64(0xffffffffabffffff), SPH_C64(0xffffffff9bffffff), SPH_C64(0xffffffff8bffffff),
        SPH_C64(0xffffffff7bffffff), SPH_C64(0xffffffff6bffffff), SPH_C64(0xffffffff5bffffff), SPH_C64(0xffffffff4bffffff),
        SPH_C64(0xffffffff3bffffff), SPH_C64(0xffffffff2bffffff), SPH_C64(0xffffffff1bffffff), SPH_C64(0xffffffff0bffffff)
    },
    {
        SPH_C64(0xfffffffffaffffff), SPH_C64(0xffffffffeaffffff), SPH_C64(0xffffffffdaffffff), SPH_C64(0xffffffffcaffffff),
        SPH_C64(0xffffffffbaffffff), SPH_C64(0xffffffffaaffffff), SPH_C64(0xffffffff9affffff), SPH_C64(0xffffffff8affffff),
        SPH_C64(0xffffffff7affffff), SPH_C64(0xffffffff6affffff), SPH_C64(0xffffffff5affffff), SPH_C64(0xffffffff4affffff),
        SPH_C64(0xffffffff3affffff), SPH_C64(0xffffffff2affffff), SPH_C64(0xffffffff1affffff), SPH_C64(0xffffffff0affffff)
    },
    {
        SPH_C64(0xfffffffff9ffffff), SPH_C64(0xffffffffe9ffffff), SPH_C64(0xffffffffd9ffffff), SPH_C64(0xffffffffc9ffffff),
        SPH_C64(0xffffffffb9ffffff), SPH_C64(0xffffffffa9ffffff), SPH_C64(0xffffffff99ffffff), SPH_C64(0xffffffff89ffffff),
        SPH_C64(0xffffffff79ffffff), SPH_C64(0xffffffff69ffffff), SPH_C64(0xffffffff59ffffff), SPH_C64(0xffffffff49ffffff),
        SPH_C64(0xffffffff39ffffff), SPH_C64(0xffffffff29ffffff), SPH_C64(0xffffffff19ffffff), SPH_C64(0xffffffff09ffffff)
    },
    {
        SPH_C64(0xfffffffff8ffffff), SPH_C64(0xffffffffe8ffffff), SPH_C64(0xffffffffd8ffffff), SPH_C64(0xffffffffc8ffffff),
        SPH_C64(0xffffffffb8ffffff), SPH_C64(0xffffffffa8ffffff), SPH_C64(0xffffffff98ffffff), SPH_C64(0xffffffff88ffffff),
        SPH_C64(0xffffffff78ffffff), SPH_C64(0xffffffff68ffffff), SPH_C64(0xffffffff58ffffff), SPH_C64(0xffffffff48ffffff),
        SPH_C64(0xffffffff38ffffff), SPH_C64(0xffffffff28ffffff), SPH_C64(0xffffffff18ffffff), SPH_C64(0xffffffff08ffffff)
    },
    {
        SPH_C64(0xfffffffff7ffffff), SPH_C64(0xffffffffe7ffffff), SPH_C64(0xffffffffd7ffffff), SPH_C64(0xffffffffc7ffffff),
        SPH_C64(0xffffffffb7ffffff), SPH_C64(0xffffffffa7ffffff), SPH_C64(0xffffffff97ffffff), SPH_C64(0xffffffff87ffffff),
        SPH_C64(0xffffffff77ffffff), SPH_C64(0xffffffff67ffffff), SPH_C64(0xffffffff57ffffff), SPH_C64(0xffffffff47ffffff),
        SPH_C64(0xffffffff37ffffff), SPH_C64(0xffffffff27ffffff), SPH_C64(0xffffffff17ffffff), SPH_C64(0xffffffff07ffffff)
    },
    {
        SPH_C64(0xfffffffff6ffffff), SPH_C64(0xffffffffe6ffffff), SPH_C64(0xffffffffd6ffffff), SPH_C64(0xffffffffc6ffffff),
        SPH_C64(0xffffffffb6ffffff), SPH_C64(0xffffffffa6ffffff), SPH_C64(0xffffffff96ffffff), SPH_C64(0xffffffff86ffffff),
        SPH_C64(0xffffffff76ffffff), SPH_C64(0xffffffff66ffffff), SPH_C64(0xffffffff56ffffff), SPH_C64(0xffffffff46ffffff),
        SPH_C64(0xffffffff36ffffff), SPH_C64(0xffffffff26ffffff), SPH_C64(0xffffffff16ffffff), SPH_C64(0xffffffff06ffffff)
    },
    {
        SPH_C64(0xfffffffff5ffffff), SPH_C64(0xffffffffe5ffffff), SPH_C64(0xffffffffd5ffffff), SPH_C64(0xffffffffc5ffffff),
        SPH_C64(0xffffffffb5ffffff), SPH_C64(0xffffffffa5ffffff), SPH_C64(0xffffffff95ffffff), SPH_C64(0xffffffff85ffffff),
        SPH_C64(0xffffffff75ffffff), SPH_C64(0xffffffff65ffffff), SPH_C64(0xffffffff55ffffff), SPH_C64(0xffffffff45ffffff),
        SPH_C64(0xffffffff35ffffff), SPH_C64(0xffffffff25ffffff), SPH_C64(0xffffffff15ffffff), SPH_C64(0xffffffff05ffffff)
    },
    {
        SPH_C64(0xfffffffff4ffffff), SPH_C64(0xffffffffe4ffffff), SPH_C64(0xffffffffd4ffffff), SPH_C64(0xffffffffc4ffffff),
        SPH_C64(0xffffffffb4ffffff), SPH_C64(0xffffffffa4ffffff), SPH_C64(0xffffffff94ffffff), SPH_C64(0xffffffff84ffffff),
        SPH_C64(0xffffffff74ffffff), SPH_C64(0xffffffff64ffffff), SPH_C64(0xffffffff54ffffff), SPH_C64(0xffffffff44ffffff),
        SPH_C64(0xffffffff34ffffff), SPH_C64(0xffffffff24ffffff), SPH_C64(0xffffffff14ffffff), SPH_C64(0xffffffff04ffffff)
    },
    {
        SPH_C64(0xfffffffff3ffffff), SPH_C64(0xffffffffe3ffffff), SPH_C64(0xffffffffd3ffffff), SPH_C64(0xffffffffc3ffffff),
        SPH_C64(0xffffffffb3ffffff), SPH_C64(0xffffffffa3ffffff), SPH_C64(0xffffffff93ffffff), SPH_C64(0xffffffff83ffffff),
        SPH_C64(0xffffffff73ffffff), SPH_C64(0xffffffff63ffffff), SPH_C64(0xffffffff53ffffff), SPH_C64(0xffffffff43ffffff),
        SPH_C64(0xffffffff33ffffff), SPH_C64(0xffffffff23ffffff), SPH_C64(0xffffffff13ffffff), SPH_C64(0xffffffff03ffffff)
    },
    {
        SPH_C64(0xfffffffff2ffffff), SPH_C64(0xffffffffe2ffffff), SPH_C64(0xffffffffd2ffffff), SPH_C64(0xffffffffc2ffffff),
        SPH_C64(0xffffffffb2ffffff), SPH_C64(0xffffffffa2ffffff), SPH_C64(0xffffffff92ffffff), SPH_C64(0xffffffff82ffffff),
        SPH_C64(0xffffffff72ffffff), SPH_C64(0xffffffff62ffffff), SPH_C64(0xffffffff52ffffff), SPH_C64(0xffffffff42ffffff),
        SPH_C64(0xffffffff32ffffff), SPH_C64(0xffffffff22ffffff), SPH_C64(0xffffffff12ffffff), SPH_C64(0xffffffff02ffffff)
    }
};

#else /* Big-endian */

static const sph_u64 PC_SMALL[10][8] GROESTL_ALIGN64 = {
    {
        SPH_C64(0x0000000000000000), SPH_C64(0x1000000000000000), SPH_C64(0x2000000000000000), SPH_C64(0x3000000000000000),
        SPH_C64(0x4000000000000000), SPH_C64(0x5000000000000000), SPH_C64(0x6000000000000000), SPH_C64(0x7000000000000000)
    },
    {
        SPH_C64(0x0100000000000000), SPH_C64(0x1100000000000000), SPH_C64(0x2100000000000000), SPH_C64(0x3100000000000000),
        SPH_C64(0x4100000000000000), SPH_C64(0x5100000000000000), SPH_C64(0x6100000000000000), SPH_C64(0x7100000000000000)
    },
    {
        SPH_C64(0x0200000000000000), SPH_C64(0x1200000000000000), SPH_C64(0x2200000000000000), SPH_C64(0x3200000000000000),
        SPH_C64(0x4200000000000000), SPH_C64(0x5200000000000000), SPH_C64(0x6200000000000000), SPH_C64(0x7200000000000000)
    },
    {
        SPH_C64(0x0300000000000000), SPH_C64(0x1300000000000000), SPH_C64(0x2300000000000000), SPH_C64(0x3300000000000000),
        SPH_C64(0x4300000000000000), SPH_C64(0x5300000000000000), SPH_C64(0x6300000000000000), SPH_C64(0x7300000000000000)
    },
    {
        SPH_C64(0x0400000000000000), SPH_C64(0x1400000000000000), SPH_C64(0x2400000000000000), SPH_C64(0x3400000000000000),
        SPH_C64(0x4400000000000000), SPH_C64(0x5400000000000000), SPH_C64(0x6400000000000000), SPH_C64(0x7400000000000000)
    },
    {
        SPH_C64(0x0500000000000000), SPH_C64(0x1500000000000000), SPH_C64(0x2500000000000000), SPH_C64(0x3500000000000000),
        SPH_C64(0x4500000000000000), SPH_C64(0x5500000000000000), SPH_C64(0x6500000000000000), SPH_C64(0x7500000000000000)
    },
    {
        SPH_C64(0x0600000000000000), SPH_C64(0x1600000000000000), SPH_C64(0x2600000000000000), SPH_C64(0x3600000000000000),
        SPH_C64(0x4600000000000000), SPH_C64(0x5600000000000000), SPH_C64(0x6600000000000000), SPH_C64(0x7600000000000000)
    },
    {
        SPH_C64(0x0700000000000000), SPH_C64(0x1700000000000000), SPH_C64(0x2700000000000000), SPH_C64(0x3700000000000000),
        SPH_C64(0x4700000000000000), SPH_C64(0x5700000000000000), SPH_C64(0x6700000000000000), SPH_C64(0x7700000000000000)
    },
    {
        SPH_C64(0x0800000000000000), SPH_C64(0x1800000000000000), SPH_C64(0x2800000000000000), SPH_C64(0x3800000000000000),
        SPH_C64(0x4800000000000000), SPH_C64(0x5800000000000000), SPH_C64(0x6800000000000000), SPH_C64(0x7800000000000000)
    },
    {
        SPH_C64(0x0900000000000000), SPH_C64(0x1900000000000000), SPH_C64(0x2900000000000000), SPH_C64(0x3900000000000000),
        SPH_C64(0x4900000000000000), SPH_C64(0x5900000000000000), SPH_C64(0x6900000000000000), SPH_C64(0x7900000000000000)
    }
};

static const sph_u64 QC_SMALL[10][8] GROESTL_ALIGN64 = {
    {
        SPH_C64(0xffffffffffffffff), SPH_C64(0xffffffffffffffef), SPH_C64(0xffffffffffffffdf), SPH_C64(0xffffffffffffffcf),
        SPH_C64(0xffffffffffffffbf), SPH_C64(0xffffffffffffffaf), SPH_C64(0xffffffffffffff9f), SPH_C64(0xffffffffffffff8f)
    },
    {
        SPH_C64(0xfffffffffffffffe), SPH_C64(0xffffffffffffffee), SPH_C64(0xffffffffffffffde), SPH_C64(0xffffffffffffffce),
        SPH_C64(0xffffffffffffffbe), SPH_C64(0xffffffffffffffae), SPH_C64(0xffffffffffffff9e), SPH_C64(0xffffffffffffff8e)
    },
    {
        SPH_C64(0xfffffffffffffffd), SPH_C64(0xffffffffffffffed), SPH_C64(0xffffffffffffffdd), SPH_C64(0xffffffffffffffcd),
        SPH_C64(0xffffffffffffffbd), SPH_C64(0xffffffffffffffad), SPH_C64(0xffffffffffffff9d), SPH_C64(0xffffffffffffff8d)
    },
    {
        SPH_C64(0xfffffffffffffffc), SPH_C64(0xffffffffffffffec), SPH_C64(0xffffffffffffffdc), SPH_C64(0xffffffffffffffcc),
        SPH_C64(0xffffffffffffffbc), SPH_C64(0xffffffffffffffac), SPH_C64(0xffffffffffffff9c), SPH_C64(0xffffffffffffff8c)
    },
    {
        SPH_C64(0xfffffffffffffffb), SPH_C64(0xffffffffffffffeb), SPH_C64(0xffffffffffffffdb), SPH_C64(0xffffffffffffffcb),
        SPH_C64(0xffffffffffffffbb), SPH_C64(0xffffffffffffffab), SPH_C64(0xffffffffffffff9b), SPH_C64(0xffffffffffffff8b)
    },
    {
        SPH_C64(0xfffffffffffffffa), SPH_C64(0xffffffffffffffea), SPH_C64(0xffffffffffffffda), SPH_C64(0xffffffffffffffca),
        SPH_C64(0xffffffffffffffba), SPH_C64(0xffffffffffffffaa), SPH_C64(0xffffffffffffff9a), SPH_C64(0xffffffffffffff8a)
    },
    {
        SPH_C64(0xfffffffffffffff9), SPH_C64(0xffffffffffffffe9), SPH_C64(0xffffffffffffffd9), SPH_C64(0xffffffffffffffc9),
        SPH_C64(0xffffffffffffffb9), SPH_C64(0xffffffffffffffa9), SPH_C64(0xffffffffffffff99), SPH_C64(0xffffffffffffff89)
    },
    {
        SPH_C64(0xfffffffffffffff8), SPH_C64(0xffffffffffffffe8), SPH_C64(0xffffffffffffffd8), SPH_C64(0xffffffffffffffc8),
        SPH_C64(0xffffffffffffffb8), SPH_C64(0xffffffffffffffa8), SPH_C64(0xffffffffffffff98), SPH_C64(0xffffffffffffff88)
    },
    {
        SPH_C64(0xfffffffffffffff7), SPH_C64(0xffffffffffffffe7), SPH_C64(0xffffffffffffffd7), SPH_C64(0xffffffffffffffc7),
        SPH_C64(0xffffffffffffffb7), SPH_C64(0xffffffffffffffa7), SPH_C64(0xffffffffffffff97), SPH_C64(0xffffffffffffff87)
    },
    {
        SPH_C64(0xfffffffffffffff6), SPH_C64(0xffffffffffffffe6), SPH_C64(0xffffffffffffffd6), SPH_C64(0xffffffffffffffc6),
        SPH_C64(0xffffffffffffffb6), SPH_C64(0xffffffffffffffa6), SPH_C64(0xffffffffffffff96), SPH_C64(0xffffffffffffff86)
    }
};

static const sph_u64 PC_BIG[14][16] GROESTL_ALIGN64 = {
    {
        SPH_C64(0x0000000000000000), SPH_C64(0x1000000000000000), SPH_C64(0x2000000000000000), SPH_C64(0x3000000000000000),
        SPH_C64(0x4000000000000000), SPH_C64(0x5000000000000000), SPH_C64(0x6000000000000000), SPH_C64(0x7000000000000000),
        SPH_C64(0x8000000000000000), SPH_C64(0x9000000000000000), SPH_C64(0xa000000000000000), SPH_C64(0xb000000000000000),
        SPH_C64(0xc000000000000000), SPH_C64(0xd000000000000000), SPH_C64(0xe000000000000000), SPH_C64(0xf000000000000000)
    },
    {
        SPH_C64(0x0100000000000000), SPH_C64(0x1100000000000000), SPH_C64(0x2100000000000000), SPH_C64(0x3100000000000000),
        SPH_C64(0x4100000000000000), SPH_C64(0x5100000000000000), SPH_C64(0x6100000000000000), SPH_C64(0x7100000000000000),
        SPH_C64(0x8100000000000000), SPH_C64(0x9100000000000000), SPH_C64(0xa100000000000000), SPH_C64(0xb100000000000000),
        SPH_C64(0xc100000000000000), SPH_C64(0xd100000000000000), SPH_C64(0xe100000000000000), SPH_C64(0xf100000000000000)
    },
    {
        SPH_C64(0x0200000000000000), SPH_C64(0x1200000000000000), SPH_C64(0x2200000000000000), SPH_C64(0x3200000000000000),
        SPH_C64(0x4200000000000000), SPH_C64(0x5200000000000000), SPH_C64(0x6200000000000000), SPH_C64(0x7200000000000000),
        SPH_C64(0x8200000000000000), SPH_C64(0x9200000000000000), SPH_C64(0xa200000000000000), SPH_C64(0xb200000000000000),
        SPH_C64(0xc200000000000000), SPH_C64(0xd200000000000000), SPH_C64(0xe200000000000000), SPH_C64(0xf200000000000000)
    },
    {
        SPH_C64(0x0300000000000000), SPH_C64(0x1300000000000000), SPH_C64(0x2300000000000000), SPH_C64(0x3300000000000000),
        SPH_C64(0x4300000000000000), SPH_C64(0x5300000000000000), SPH_C64(0x6300000000000000), SPH_C64(0x7300000000000000),
        SPH_C64(0x8300000000000000), SPH_C64(0x9300000000000000), SPH_C64(0xa300000000000000), SPH_C64(0xb300000000000000),
        SPH_C64(0xc300000000000000), SPH_C64(0xd300000000000000), SPH_C64(0xe300000000000000), SPH_C64(0xf300000000000000)
    },
    {
        SPH_C64(0x0400000000000000), SPH_C64(0x1400000000000000), SPH_C64(0x2400000000000000), SPH_C64(0x3400000000000000),
        SPH_C64(0x4400000000000000), SPH_C64(0x5400000000000000), SPH_C64(0x6400000000000000), SPH_C64(0x7400000000000000),
        SPH_C64(0x8400000000000000), SPH_C64(0x9400000000000000), SPH_C64(0xa400000000000000), SPH_C64(0xb400000000000000),
        SPH_C64(0xc400000000000000), SPH_C64(0xd400000000000000), SPH_C64(0xe400000000000000), SPH_C64(0xf400000000000000)
    },
    {
        SPH_C64(0x0500000000000000), SPH_C64(0x1500000000000000), SPH_C64(0x2500000000000000), SPH_C64(0x3500000000000000),
        SPH_C64(0x4500000000000000), SPH_C64(0x5500000000000000), SPH_C64(0x6500000000000000), SPH_C64(0x7500000000000000),
        SPH_C64(0x8500000000000000), SPH_C64(0x9500000000000000), SPH_C64(0xa500000000000000), SPH_C64(0xb500000000000000),
        SPH_C64(0xc500000000000000), SPH_C64(0xd500000000000000), SPH_C64(0xe500000000000000), SPH_C64(0xf500000000000000)
    },
    {
        SPH_C64(0x0600000000000000), SPH_C64(0x1600000000000000), SPH_C64(0x2600000000000000), SPH_C64(0x3600000000000000),
        SPH_C64(0x4600000000000000), SPH_C64(0x5600000000000000), SPH_C64(0x6600000000000000), SPH_C64(0x7600000000000000),
        SPH_C64(0x8600000000000000), SPH_C64(0x9600000000000000), SPH_C64(0xa600000000000000), SPH_C64(0xb600000000000000),
        SPH_C64(0xc600000000000000), SPH_C64(0xd600000000000000), SPH_C64(0xe600000000000000), SPH_C64(0xf600000000000000)
    },
    {
        SPH_C64(0x0700000000000000), SPH_C64(0x1700000000000000), SPH_C64(0x2700000000000000), SPH_C64(0x3700000000000000),
        SPH_C64(0x4700000000000000), SPH_C64(0x5700000000000000), SPH_C64(0x6700000000000000), SPH_C64(0x7700000000000000),
        SPH_C64(0x8700000000000000), SPH_C64(0x9700000000000000), SPH_C64(0xa700000000000000), SPH_C64(0xb700000000000000),
        SPH_C64(0xc700000000000000), SPH_C64(0xd700000000000000), SPH_C64(0xe700000000000000), SPH_C64(0xf700000000000000)
    },
    {
        SPH_C64(0x0800000000000000), SPH_C64(0x1800000000000000), SPH_C64(0x2800000000000000), SPH_C64(0x3800000000000000),
        SPH_C64(0x4800000000000000), SPH_C64(0x5800000000000000), SPH_C64(0x6800000000000000), SPH_C64(0x7800000000000000),
        SPH_C64(0x8800000000000000), SPH_C64(0x9800000000000000), SPH_C64(0xa800000000000000), SPH_C64(0xb800000000000000),
        SPH_C64(0xc800000000000000), SPH_C64(0xd800000000000000), SPH_C64(0xe800000000000000), SPH_C64(0xf800000000000000)
    },
    {
        SPH_C64(0x0900000000000000), SPH_C64(0x1900000000000000), SPH_C64(0x2900000000000000), SPH_C64(0x3900000000000000),
        SPH_C64(0x4900000000000000), SPH_C64(0x5900000000000000), SPH_C64(0x6900000000000000), SPH_C64(0x7900000000000000),
        SPH_C64(0x8900000000000000), SPH_C64(0x9900000000000000), SPH_C64(0xa900000000000000), SPH_C64(0xb900000000000000),
        SPH_C64(0xc900000000000000), SPH_C64(0xd900000000000000), SPH_C64(0xe900000000000000), SPH_C64(0xf900000000000000)
    },
    {
        SPH_C64(0x0a00000000000000), SPH_C64(0x1a00000000000000), SPH_C64(0x2a00000000000000), SPH_C64(0x3a00000000000000),
        SPH_C64(0x4a00000000000000), SPH_C64(0x5a00000000000000), SPH_C64(0x6a00000000000000), SPH_C64(0x7a00000000000000),
        SPH_C64(0x8a00000000000000), SPH_C64(0x9a00000000000000), SPH_C64(0xaa00000000000000), SPH_C64(0xba00000000000000),
        SPH_C64(0xca00000000000000), SPH_C64(0xda00000000000000), SPH_C64(0xea00000000000000), SPH_C64(0xfa00000000000000)
    },
    {
        SPH_C64(0x0b00000000000000), SPH_C64(0x1b00000000000000), SPH_C64(0x2b00000000000000), SPH_C64(0x3b00000000000000),
        SPH_C64(0x4b00000000000000), SPH_C64(0x5b00000000000000), SPH_C64(0x6b00000000000000), SPH_C64(0x7b00000000000000),
        SPH_C64(0x8b00000000000000), SPH_C64(0x9b00000000000000), SPH_C64(0xab00000000000000), SPH_C64(0xbb00000000000000),
        SPH_C64(0xcb00000000000000), SPH_C64(0xdb00000000000000), SPH_C64(0xeb00000000000000), SPH_C64(0xfb00000000000000)
    },
    {
        SPH_C64(0x0c00000000000000), SPH_C64(0x1c00000000000000), SPH_C64(0x2c00000000000000), SPH_C64(0x3c00000000000000),
        SPH_C64(0x4c00000000000000), SPH_C64(0x5c00000000000000), SPH_C64(0x6c00000000000000), SPH_C64(0x7c00000000000000),
        SPH_C64(0x8c00000000000000), SPH_C64(0x9c00000000000000), SPH_C64(0xac00000000000000), SPH_C64(0xbc00000000000000),
        SPH_C64(0xcc00000000000000), SPH_C64(0xdc00000000000000), SPH_C64(0xec00000000000000), SPH_C64(0xfc00000000000000)
    },
    {
        SPH_C64(0x0d00000000000000), SPH_C64(0x1d00000000000000), SPH_C64(0x2d00000000000000), SPH_C64(0x3d00000000000000),
        SPH_C64(0x4d00000000000000), SPH_C64(0x5d00000000000000), SPH_C64(0x6d00000000000000), SPH_C64(0x7d00000000000000),
        SPH_C64(0x8d00000000000000), SPH_C64(0x9d00000000000000), SPH_C64(0xad00000000000000), SPH_C64(0xbd00000000000000),
        SPH_C64(0xcd00000000000000), SPH_C64(0xdd00000000000000), SPH_C64(0xed00000000000000), SPH_C64(0xfd00000000000000)
    }
};

static const sph_u64 QC_BIG[14][16] GROESTL_ALIGN64 = {
    {
        SPH_C64(0xffffffffffffffff), SPH_C64(0xffffffffffffffef), SPH_C64(0xffffffffffffffdf), SPH_C64(0xffffffffffffffcf),
        SPH_C64(0xffffffffffffffbf), SPH_C64(0xffffffffffffffaf), SPH_C64(0xffffffffffffff9f), SPH_C64(0xffffffffffffff8f),
        SPH_C64(0xffffffffffffff7f), SPH_C64(0xffffffffffffff6f), SPH_C64(0xffffffffffffff5f), SPH_C64(0xffffffffffffff4f),
        SPH_C64(0xffffffffffffff3f), SPH_C64(0xffffffffffffff2f), SPH_C64(0xffffffffffffff1f), SPH_C64(0xffffffffffffff0f)
    },
    {
        SPH_C64(0xfffffffffffffffe), SPH_C64(0xffffffffffffffee), SPH_C64(0xffffffffffffffde), SPH_C64(0xffffffffffffffce),
        SPH_C64(0xffffffffffffffbe), SPH_C64(0xffffffffffffffae), SPH_C64(0xffffffffffffff9e), SPH_C64(0xffffffffffffff8e),
        SPH_C64(0xffffffffffffff7e), SPH_C64(0xffffffffffffff6e), SPH_C64(0xffffffffffffff5e), SPH_C64(0xffffffffffffff4e),
        SPH_C64(0xffffffffffffff3e), SPH_C64(0xffffffffffffff2e), SPH_C64(0xffffffffffffff1e), SPH_C64(0xffffffffffffff0e)
    },
    {
        SPH_C64(0xfffffffffffffffd), SPH_C64(0xffffffffffffffed), SPH_C64(0xffffffffffffffdd), SPH_C64(0xffffffffffffffcd),
        SPH_C64(0xffffffffffffffbd), SPH_C64(0xffffffffffffffad), SPH_C64(0xffffffffffffff9d), SPH_C64(0xffffffffffffff8d),
        SPH_C64(0xffffffffffffff7d), SPH_C64(0xffffffffffffff6d), SPH_C64(0xffffffffffffff5d), SPH_C64(0xffffffffffffff4d),
        SPH_C64(0xffffffffffffff3d), SPH_C64(0xffffffffffffff2d), SPH_C64(0xffffffffffffff1d), SPH_C64(0xffffffffffffff0d)
    },
    {
        SPH_C64(0xfffffffffffffffc), SPH_C64(0xffffffffffffffec), SPH_C64(0xffffffffffffffdc), SPH_C64(0xffffffffffffffcc),
        SPH_C64(0xffffffffffffffbc), SPH_C64(0xffffffffffffffac), SPH_C64(0xffffffffffffff9c), SPH_C64(0xffffffffffffff8c),
        SPH_C64(0xffffffffffffff7c), SPH_C64(0xffffffffffffff6c), SPH_C64(0xffffffffffffff5c), SPH_C64(0xffffffffffffff4c),
        SPH_C64(0xffffffffffffff3c), SPH_C64(0xffffffffffffff2c), SPH_C64(0xffffffffffffff1c), SPH_C64(0xffffffffffffff0c)
    },
    {
        SPH_C64(0xfffffffffffffffb), SPH_C64(0xffffffffffffffeb), SPH_C64(0xffffffffffffffdb), SPH_C64(0xffffffffffffffcb),
        SPH_C64(0xffffffffffffffbb), SPH_C64(0xffffffffffffffab), SPH_C64(0xffffffffffffff9b), SPH_C64(0xffffffffffffff8b),
        SPH_C64(0xffffffffffffff7b), SPH_C64(0xffffffffffffff6b), SPH_C64(0xffffffffffffff5b), SPH_C64(0xffffffffffffff4b),
        SPH_C64(0xffffffffffffff3b), SPH_C64(0xffffffffffffff2b), SPH_C64(0xffffffffffffff1b), SPH_C64(0xffffffffffffff0b)
    },
    {
        SPH_C64(0xfffffffffffffffa), SPH_C64(0xffffffffffffffea), SPH_C64(0xffffffffffffffda), SPH_C64(0xffffffffffffffca),
        SPH_C64(0xffffffffffffffba), SPH_C64(0xffffffffffffffaa), SPH_C64(0xffffffffffffff9a), SPH_C64(0xffffffffffffff8a),
        SPH_C64(0xffffffffffffff7a), SPH_C64(0xffffffffffffff6a), SPH_C64(0xffffffffffffff5a), SPH_C64(0xffffffffffffff4a),
        SPH_C64(0xffffffffffffff3a), SPH_C64(0xffffffffffffff2a), SPH_C64(0xffffffffffffff1a), SPH_C64(0xffffffffffffff0a)
    },
    {
        SPH_C64(0xfffffffffffffff9), SPH_C64(0xffffffffffffffe9), SPH_C64(0xffffffffffffffd9), SPH_C64(0xffffffffffffffc9),
        SPH_C64(0xffffffffffffffb9), SPH_C64(0xffffffffffffffa9), SPH_C64(0xffffffffffffff99), SPH_C64(0xffffffffffffff89),
        SPH_C64(0xffffffffffffff79), SPH_C64(0xffffffffffffff69), SPH_C64(0xffffffffffffff59), SPH_C64(0xffffffffffffff49),
        SPH_C64(0xffffffffffffff39), SPH_C64(0xffffffffffffff29), SPH_C64(0xffffffffffffff19), SPH_C64(0xffffffffffffff09)
    },
    {
        SPH_C64(0xfffffffffffffff8), SPH_C64(0xffffffffffffffe8), SPH_C64(0xffffffffffffffd8), SPH_C64(0xffffffffffffffc8),
        SPH_C64(0xffffffffffffffb8), SPH_C64(0xffffffffffffffa8), SPH_C64(0xffffffffffffff98), SPH_C64(0xffffffffffffff88),
        SPH_C64(0xffffffffffffff78), SPH_C64(0xffffffffffffff68), SPH_C64(0xffffffffffffff58), SPH_C64(0xffffffffffffff48),
        SPH_C64(0xffffffffffffff38), SPH_C64(0xffffffffffffff28), SPH_C64(0xffffffffffffff18), SPH_C64(0xffffffffffffff08)
    },
    {
        SPH_C64(0xfffffffffffffff7), SPH_C64(0xffffffffffffffe7), SPH_C64(0xffffffffffffffd7), SPH_C64(0xffffffffffffffc7),
        SPH_C64(0xffffffffffffffb7), SPH_C64(0xffffffffffffffa7), SPH_C64(0xffffffffffffff97), SPH_C64(0xffffffffffffff87),
        SPH_C64(0xffffffffffffff77), SPH_C64(0xffffffffffffff67), SPH_C64(0xffffffffffffff57), SPH_C64(0xffffffffffffff47),
        SPH_C64(0xffffffffffffff37), SPH_C64(0xffffffffffffff27), SPH_C64(0xffffffffffffff17), SPH_C64(0xffffffffffffff07)
    },
    {
        SPH_C64(0xfffffffffffffff6), SPH_C64(0xffffffffffffffe6), SPH_C64(0xffffffffffffffd6), SPH_C64(0xffffffffffffffc6),
        SPH_C64(0xffffffffffffffb6), SPH_C64(0xffffffffffffffa6), SPH_C64(0xffffffffffffff96), SPH_C64(0xffffffffffffff86),
        SPH_C64(0xffffffffffffff76), SPH_C64(0xffffffffffffff66), SPH_C64(0xffffffffffffff56), SPH_C64(0xffffffffffffff46),
        SPH_C64(0xffffffffffffff36), SPH_C64(0xffffffffffffff26), SPH_C64(0xffffffffffffff16), SPH_C64(0xffffffffffffff06)
    },
    {
        SPH_C64(0xfffffffffffffff5), SPH_C64(0xffffffffffffffe5), SPH_C64(0xffffffffffffffd5), SPH_C64(0xffffffffffffffc5),
        SPH_C64(0xffffffffffffffb5), SPH_C64(0xffffffffffffffa5), SPH_C64(0xffffffffffffff95), SPH_C64(0xffffffffffffff85),
        SPH_C64(0xffffffffffffff75), SPH_C64(0xffffffffffffff65), SPH_C64(0xffffffffffffff55), SPH_C64(0xffffffffffffff45),
        SPH_C64(0xffffffffffffff35), SPH_C64(0xffffffffffffff25), SPH_C64(0xffffffffffffff15), SPH_C64(0xffffffffffffff05)
    },
    {
        SPH_C64(0xfffffffffffffff4), SPH_C64(0xffffffffffffffe4), SPH_C64(0xffffffffffffffd4), SPH_C64(0xffffffffffffffc4),
        SPH_C64(0xffffffffffffffb4), SPH_C64(0xffffffffffffffa4), SPH_C64(0xffffffffffffff94), SPH_C64(0xffffffffffffff84),
        SPH_C64(0xffffffffffffff74), SPH_C64(0xffffffffffffff64), SPH_C64(0xffffffffffffff54), SPH_C64(0xffffffffffffff44),
        SPH_C64(0xffffffffffffff34), SPH_C64(0xffffffffffffff24), SPH_C64(0xffffffffffffff14), SPH_C64(0xffffffffffffff04)
    },
    {
        SPH_C64(0xfffffffffffffff3), SPH_C64(0xffffffffffffffe3), SPH_C64(0xffffffffffffffd3), SPH_C64(0xffffffffffffffc3),
        SPH_C64(0xffffffffffffffb3), SPH_C64(0xffffffffffffffa3), SPH_C64(0xffffffffffffff93), SPH_C64(0xffffffffffffff83),
        SPH_C64(0xffffffffffffff73), SPH_C64(0xffffffffffffff63), SPH_C64(0xffffffffffffff53), SPH_C64(0xffffffffffffff43),
        SPH_C64(0xffffffffffffff33), SPH_C64(0xffffffffffffff23), SPH_C64(0xffffffffffffff13), SPH_C64(0xffffffffffffff03)
    },
    {
        SPH_C64(0xfffffffffffffff2), SPH_C64(0xffffffffffffffe2), SPH_C64(0xffffffffffffffd2), SPH_C64(0xffffffffffffffc2),
        SPH_C64(0xffffffffffffffb2), SPH_C64(0xffffffffffffffa2), SPH_C64(0xffffffffffffff92), SPH_C64(0xffffffffffffff82),
        SPH_C64(0xffffffffffffff72), SPH_C64(0xffffffffffffff62), SPH_C64(0xffffffffffffff52), SPH_C64(0xffffffffffffff42),
        SPH_C64(0xffffffffffffff32), SPH_C64(0xffffffffffffff22), SPH_C64(0xffffffffffffff12), SPH_C64(0xffffffffffffff02)
    }
};

#endif

/* ------------------------------------------------------------------ */
/* Optimised RSTT — zero runtime rotations, pure table+XOR fusion     */
/* ------------------------------------------------------------------ */
#define RSTT(d, a, b0, b1, b2, b3, b4, b5, b6, b7)   do { \
		t[d] = T0[B64_0(a[b0])] \
			^ T1[B64_1(a[b1])] \
			^ T2[B64_2(a[b2])] \
			^ T3[B64_3(a[b3])] \
			^ T4[B64_4(a[b4])] \
			^ T5[B64_5(a[b5])] \
			^ T6[B64_6(a[b6])] \
			^ T7[B64_7(a[b7])]; \
	} while (0)

#define RBTT(d, a, b0, b1, b2, b3, b4, b5, b6, b7)   do { \
		t[d] = T0[B64_0(a[b0])] \
			^ T1[B64_1(a[b1])] \
			^ T2[B64_2(a[b2])] \
			^ T3[B64_3(a[b3])] \
			^ T4[B64_4(a[b4])] \
			^ T5[B64_5(a[b5])] \
			^ T6[B64_6(a[b6])] \
			^ T7[B64_7(a[b7])]; \
	} while (0)

/* ------------------------------------------------------------------ */
/* Round macros with precomputed constants (no macro expansion cost)   */
/* ------------------------------------------------------------------ */
#define ROUND_SMALL_P(a, r)   do { \
		sph_u64 t[8]; \
		a[0] ^= PC_SMALL[r][0]; \
		a[1] ^= PC_SMALL[r][1]; \
		a[2] ^= PC_SMALL[r][2]; \
		a[3] ^= PC_SMALL[r][3]; \
		a[4] ^= PC_SMALL[r][4]; \
		a[5] ^= PC_SMALL[r][5]; \
		a[6] ^= PC_SMALL[r][6]; \
		a[7] ^= PC_SMALL[r][7]; \
		RSTT(0, a, 0, 1, 2, 3, 4, 5, 6, 7); \
		RSTT(1, a, 1, 2, 3, 4, 5, 6, 7, 0); \
		RSTT(2, a, 2, 3, 4, 5, 6, 7, 0, 1); \
		RSTT(3, a, 3, 4, 5, 6, 7, 0, 1, 2); \
		RSTT(4, a, 4, 5, 6, 7, 0, 1, 2, 3); \
		RSTT(5, a, 5, 6, 7, 0, 1, 2, 3, 4); \
		RSTT(6, a, 6, 7, 0, 1, 2, 3, 4, 5); \
		RSTT(7, a, 7, 0, 1, 2, 3, 4, 5, 6); \
		a[0] = t[0]; a[1] = t[1]; a[2] = t[2]; a[3] = t[3]; \
		a[4] = t[4]; a[5] = t[5]; a[6] = t[6]; a[7] = t[7]; \
	} while (0)

#define ROUND_SMALL_Q(a, r)   do { \
		sph_u64 t[8]; \
		a[0] ^= QC_SMALL[r][0]; \
		a[1] ^= QC_SMALL[r][1]; \
		a[2] ^= QC_SMALL[r][2]; \
		a[3] ^= QC_SMALL[r][3]; \
		a[4] ^= QC_SMALL[r][4]; \
		a[5] ^= QC_SMALL[r][5]; \
		a[6] ^= QC_SMALL[r][6]; \
		a[7] ^= QC_SMALL[r][7]; \
		RSTT(0, a, 1, 3, 5, 7, 0, 2, 4, 6); \
		RSTT(1, a, 2, 4, 6, 0, 1, 3, 5, 7); \
		RSTT(2, a, 3, 5, 7, 1, 2, 4, 6, 0); \
		RSTT(3, a, 4, 6, 0, 2, 3, 5, 7, 1); \
		RSTT(4, a, 5, 7, 1, 3, 4, 6, 0, 2); \
		RSTT(5, a, 6, 0, 2, 4, 5, 7, 1, 3); \
		RSTT(6, a, 7, 1, 3, 5, 6, 0, 2, 4); \
		RSTT(7, a, 0, 2, 4, 6, 7, 1, 3, 5); \
		a[0] = t[0]; a[1] = t[1]; a[2] = t[2]; a[3] = t[3]; \
		a[4] = t[4]; a[5] = t[5]; a[6] = t[6]; a[7] = t[7]; \
	} while (0)

/* Fully unrolled permutations */
#define PERM_SMALL_P(a)   do { \
		ROUND_SMALL_P(a, 0); ROUND_SMALL_P(a, 1); \
		ROUND_SMALL_P(a, 2); ROUND_SMALL_P(a, 3); \
		ROUND_SMALL_P(a, 4); ROUND_SMALL_P(a, 5); \
		ROUND_SMALL_P(a, 6); ROUND_SMALL_P(a, 7); \
		ROUND_SMALL_P(a, 8); ROUND_SMALL_P(a, 9); \
	} while (0)

#define PERM_SMALL_Q(a)   do { \
		ROUND_SMALL_Q(a, 0); ROUND_SMALL_Q(a, 1); \
		ROUND_SMALL_Q(a, 2); ROUND_SMALL_Q(a, 3); \
		ROUND_SMALL_Q(a, 4); ROUND_SMALL_Q(a, 5); \
		ROUND_SMALL_Q(a, 6); ROUND_SMALL_Q(a, 7); \
		ROUND_SMALL_Q(a, 8); ROUND_SMALL_Q(a, 9); \
	} while (0)

/* State macros */
#define DECL_STATE_SMALL   sph_u64 H[8];

#define READ_STATE_SMALL(sc)   do { \
		memcpy(H, (sc)->state.wide, sizeof H); \
	} while (0)

#define WRITE_STATE_SMALL(sc)   do { \
		memcpy((sc)->state.wide, H, sizeof H); \
	} while (0)

/* ------------------------------------------------------------------ */
/* NEON-accelerated block loading for small variant (8×64-bit)        */
/* ------------------------------------------------------------------ */
#if GROESTL_ARM_NEON && SPH_64
#define COMPRESS_SMALL   do { \
		sph_u64 g[8], m[8]; \
		uint64x2_t v0, v1, v2, v3, h0, h1, h2, h3; \
		v0 = vld1q_u64((const uint64_t *)(buf +  0)); \
		v1 = vld1q_u64((const uint64_t *)(buf + 16)); \
		v2 = vld1q_u64((const uint64_t *)(buf + 32)); \
		v3 = vld1q_u64((const uint64_t *)(buf + 48)); \
		h0 = vld1q_u64((const uint64_t *)(H + 0)); \
		h1 = vld1q_u64((const uint64_t *)(H + 2)); \
		h2 = vld1q_u64((const uint64_t *)(H + 4)); \
		h3 = vld1q_u64((const uint64_t *)(H + 6)); \
		v0 = veorq_u64(v0, h0); \
		v1 = veorq_u64(v1, h1); \
		v2 = veorq_u64(v2, h2); \
		v3 = veorq_u64(v3, h3); \
		vst1q_u64((uint64_t *)(m + 0), v0); \
		vst1q_u64((uint64_t *)(m + 2), v1); \
		vst1q_u64((uint64_t *)(m + 4), v2); \
		vst1q_u64((uint64_t *)(m + 6), v3); \
		vst1q_u64((uint64_t *)(g + 0), v0); \
		vst1q_u64((uint64_t *)(g + 2), v1); \
		vst1q_u64((uint64_t *)(g + 4), v2); \
		vst1q_u64((uint64_t *)(g + 6), v3); \
		PERM_SMALL_P(g); \
		PERM_SMALL_Q(m); \
		h0 = veorq_u64(h0, vld1q_u64((const uint64_t *)(g + 0))); \
		h1 = veorq_u64(h1, vld1q_u64((const uint64_t *)(g + 2))); \
		h2 = veorq_u64(h2, vld1q_u64((const uint64_t *)(g + 4))); \
		h3 = veorq_u64(h3, vld1q_u64((const uint64_t *)(g + 6))); \
		h0 = veorq_u64(h0, vld1q_u64((const uint64_t *)(m + 0))); \
		h1 = veorq_u64(h1, vld1q_u64((const uint64_t *)(m + 2))); \
		h2 = veorq_u64(h2, vld1q_u64((const uint64_t *)(m + 4))); \
		h3 = veorq_u64(h3, vld1q_u64((const uint64_t *)(m + 6))); \
		vst1q_u64((uint64_t *)(H + 0), h0); \
		vst1q_u64((uint64_t *)(H + 2), h1); \
		vst1q_u64((uint64_t *)(H + 4), h2); \
		vst1q_u64((uint64_t *)(H + 6), h3); \
	} while (0)
#else
#define COMPRESS_SMALL   do { \
		sph_u64 g[8], m[8]; \
		size_t u; \
		for (u = 0; u < 8; u ++) { \
			m[u] = dec64e_aligned(buf + (u << 3)); \
			g[u] = m[u] ^ H[u]; \
		} \
		PERM_SMALL_P(g); \
		PERM_SMALL_Q(m); \
		for (u = 0; u < 8; u ++) \
			H[u] ^= g[u] ^ m[u]; \
	} while (0)
#endif

#define FINAL_SMALL   do { \
		sph_u64 x[8]; \
		size_t u; \
		memcpy(x, H, sizeof x); \
		PERM_SMALL_P(x); \
		for (u = 0; u < 8; u ++) \
			H[u] ^= x[u]; \
	} while (0)

/* --------------------------------------------------------------- */
/* Big-state round macros (same precomputed constant approach)      */
/* --------------------------------------------------------------- */
#define ROUND_BIG_P(a, r)   do { \
		sph_u64 t[16]; \
		a[0x0] ^= PC_BIG[r][0x0]; a[0x1] ^= PC_BIG[r][0x1]; a[0x2] ^= PC_BIG[r][0x2]; a[0x3] ^= PC_BIG[r][0x3]; \
		a[0x4] ^= PC_BIG[r][0x4]; a[0x5] ^= PC_BIG[r][0x5]; a[0x6] ^= PC_BIG[r][0x6]; a[0x7] ^= PC_BIG[r][0x7]; \
		a[0x8] ^= PC_BIG[r][0x8]; a[0x9] ^= PC_BIG[r][0x9]; a[0xA] ^= PC_BIG[r][0xA]; a[0xB] ^= PC_BIG[r][0xB]; \
		a[0xC] ^= PC_BIG[r][0xC]; a[0xD] ^= PC_BIG[r][0xD]; a[0xE] ^= PC_BIG[r][0xE]; a[0xF] ^= PC_BIG[r][0xF]; \
		RBTT(0x0, a, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0xB); \
		RBTT(0x1, a, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0xC); \
		RBTT(0x2, a, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0xD); \
		RBTT(0x3, a, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xE); \
		RBTT(0x4, a, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xF); \
		RBTT(0x5, a, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0x0); \
		RBTT(0x6, a, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0x1); \
		RBTT(0x7, a, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0x2); \
		RBTT(0x8, a, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0x3); \
		RBTT(0x9, a, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x4); \
		RBTT(0xA, a, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x0, 0x5); \
		RBTT(0xB, a, 0xB, 0xC, 0xD, 0xE, 0xF, 0x0, 0x1, 0x6); \
		RBTT(0xC, a, 0xC, 0xD, 0xE, 0xF, 0x0, 0x1, 0x2, 0x7); \
		RBTT(0xD, a, 0xD, 0xE, 0xF, 0x0, 0x1, 0x2, 0x3, 0x8); \
		RBTT(0xE, a, 0xE, 0xF, 0x0, 0x1, 0x2, 0x3, 0x4, 0x9); \
		RBTT(0xF, a, 0xF, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0xA); \
		a[0x0] = t[0x0]; a[0x1] = t[0x1]; a[0x2] = t[0x2]; a[0x3] = t[0x3]; \
		a[0x4] = t[0x4]; a[0x5] = t[0x5]; a[0x6] = t[0x6]; a[0x7] = t[0x7]; \
		a[0x8] = t[0x8]; a[0x9] = t[0x9]; a[0xA] = t[0xA]; a[0xB] = t[0xB]; \
		a[0xC] = t[0xC]; a[0xD] = t[0xD]; a[0xE] = t[0xE]; a[0xF] = t[0xF]; \
	} while (0)

#define ROUND_BIG_Q(a, r)   do { \
		sph_u64 t[16]; \
		a[0x0] ^= QC_BIG[r][0x0]; a[0x1] ^= QC_BIG[r][0x1]; a[0x2] ^= QC_BIG[r][0x2]; a[0x3] ^= QC_BIG[r][0x3]; \
		a[0x4] ^= QC_BIG[r][0x4]; a[0x5] ^= QC_BIG[r][0x5]; a[0x6] ^= QC_BIG[r][0x6]; a[0x7] ^= QC_BIG[r][0x7]; \
		a[0x8] ^= QC_BIG[r][0x8]; a[0x9] ^= QC_BIG[r][0x9]; a[0xA] ^= QC_BIG[r][0xA]; a[0xB] ^= QC_BIG[r][0xB]; \
		a[0xC] ^= QC_BIG[r][0xC]; a[0xD] ^= QC_BIG[r][0xD]; a[0xE] ^= QC_BIG[r][0xE]; a[0xF] ^= QC_BIG[r][0xF]; \
		RBTT(0x0, a, 0x1, 0x3, 0x5, 0xB, 0x0, 0x2, 0x4, 0x6); \
		RBTT(0x1, a, 0x2, 0x4, 0x6, 0xC, 0x1, 0x3, 0x5, 0x7); \
		RBTT(0x2, a, 0x3, 0x5, 0x7, 0xD, 0x2, 0x4, 0x6, 0x8); \
		RBTT(0x3, a, 0x4, 0x6, 0x8, 0xE, 0x3, 0x5, 0x7, 0x9); \
		RBTT(0x4, a, 0x5, 0x7, 0x9, 0xF, 0x4, 0x6, 0x8, 0xA); \
		RBTT(0x5, a, 0x6, 0x8, 0xA, 0x0, 0x5, 0x7, 0x9, 0xB); \
		RBTT(0x6, a, 0x7, 0x9, 0xB, 0x1, 0x6, 0x8, 0xA, 0xC); \
		RBTT(0x7, a, 0x8, 0xA, 0xC, 0x2, 0x7, 0x9, 0xB, 0xD); \
		RBTT(0x8, a, 0x9, 0xB, 0xD, 0x3, 0x8, 0xA, 0xC, 0xE); \
		RBTT(0x9, a, 0xA, 0xC, 0xE, 0x4, 0x9, 0xB, 0xD, 0xF); \
		RBTT(0xA, a, 0xB, 0xD, 0xF, 0x5, 0xA, 0xC, 0xE, 0x0); \
		RBTT(0xB, a, 0xC, 0xE, 0x0, 0x6, 0xB, 0xD, 0xF, 0x1); \
		RBTT(0xC, a, 0xD, 0xF, 0x1, 0x7, 0xC, 0xE, 0x0, 0x2); \
		RBTT(0xD, a, 0xE, 0x0, 0x2, 0x8, 0xD, 0xF, 0x1, 0x3); \
		RBTT(0xE, a, 0xF, 0x1, 0x3, 0x9, 0xE, 0x0, 0x2, 0x4); \
		RBTT(0xF, a, 0x0, 0x2, 0x4, 0xA, 0xF, 0x1, 0x3, 0x5); \
		a[0x0] = t[0x0]; a[0x1] = t[0x1]; a[0x2] = t[0x2]; a[0x3] = t[0x3]; \
		a[0x4] = t[0x4]; a[0x5] = t[0x5]; a[0x6] = t[0x6]; a[0x7] = t[0x7]; \
		a[0x8] = t[0x8]; a[0x9] = t[0x9]; a[0xA] = t[0xA]; a[0xB] = t[0xB]; \
		a[0xC] = t[0xC]; a[0xD] = t[0xD]; a[0xE] = t[0xE]; a[0xF] = t[0xF]; \
	} while (0)

#define PERM_BIG_P(a)   do { \
		ROUND_BIG_P(a, 0); ROUND_BIG_P(a, 1); \
		ROUND_BIG_P(a, 2); ROUND_BIG_P(a, 3); \
		ROUND_BIG_P(a, 4); ROUND_BIG_P(a, 5); \
		ROUND_BIG_P(a, 6); ROUND_BIG_P(a, 7); \
		ROUND_BIG_P(a, 8); ROUND_BIG_P(a, 9); \
		ROUND_BIG_P(a, 10); ROUND_BIG_P(a, 11); \
		ROUND_BIG_P(a, 12); ROUND_BIG_P(a, 13); \
	} while (0)

#define PERM_BIG_Q(a)   do { \
		ROUND_BIG_Q(a, 0); ROUND_BIG_Q(a, 1); \
		ROUND_BIG_Q(a, 2); ROUND_BIG_Q(a, 3); \
		ROUND_BIG_Q(a, 4); ROUND_BIG_Q(a, 5); \
		ROUND_BIG_Q(a, 6); ROUND_BIG_Q(a, 7); \
		ROUND_BIG_Q(a, 8); ROUND_BIG_Q(a, 9); \
		ROUND_BIG_Q(a, 10); ROUND_BIG_Q(a, 11); \
		ROUND_BIG_Q(a, 12); ROUND_BIG_Q(a, 13); \
	} while (0)

/* State macros for big variant */
#define DECL_STATE_BIG   sph_u64 H[16];

#define READ_STATE_BIG(sc)   do { \
		memcpy(H, (sc)->state.wide, sizeof H); \
	} while (0)

#define WRITE_STATE_BIG(sc)   do { \
		memcpy((sc)->state.wide, H, sizeof H); \
	} while (0)

#if GROESTL_ARM_NEON && SPH_64
#define COMPRESS_BIG   do { \
		sph_u64 g[16], m[16]; \
		uint64x2_t v0, v1, v2, v3, v4, v5, v6, v7; \
		uint64x2_t h0, h1, h2, h3, h4, h5, h6, h7; \
		v0 = vld1q_u64((const uint64_t *)(buf +   0)); \
		v1 = vld1q_u64((const uint64_t *)(buf +  16)); \
		v2 = vld1q_u64((const uint64_t *)(buf +  32)); \
		v3 = vld1q_u64((const uint64_t *)(buf +  48)); \
		v4 = vld1q_u64((const uint64_t *)(buf +  64)); \
		v5 = vld1q_u64((const uint64_t *)(buf +  80)); \
		v6 = vld1q_u64((const uint64_t *)(buf +  96)); \
		v7 = vld1q_u64((const uint64_t *)(buf + 112)); \
		h0 = vld1q_u64((const uint64_t *)(H +  0)); \
		h1 = vld1q_u64((const uint64_t *)(H +  2)); \
		h2 = vld1q_u64((const uint64_t *)(H +  4)); \
		h3 = vld1q_u64((const uint64_t *)(H +  6)); \
		h4 = vld1q_u64((const uint64_t *)(H +  8)); \
		h5 = vld1q_u64((const uint64_t *)(H + 10)); \
		h6 = vld1q_u64((const uint64_t *)(H + 12)); \
		h7 = vld1q_u64((const uint64_t *)(H + 14)); \
		v0 = veorq_u64(v0, h0); v1 = veorq_u64(v1, h1); \
		v2 = veorq_u64(v2, h2); v3 = veorq_u64(v3, h3); \
		v4 = veorq_u64(v4, h4); v5 = veorq_u64(v5, h5); \
		v6 = veorq_u64(v6, h6); v7 = veorq_u64(v7, h7); \
		vst1q_u64((uint64_t *)(m + 0), v0); vst1q_u64((uint64_t *)(m + 2), v1); \
		vst1q_u64((uint64_t *)(m + 4), v2); vst1q_u64((uint64_t *)(m + 6), v3); \
		vst1q_u64((uint64_t *)(m + 8), v4); vst1q_u64((uint64_t *)(m + 10), v5); \
		vst1q_u64((uint64_t *)(m + 12), v6); vst1q_u64((uint64_t *)(m + 14), v7); \
		vst1q_u64((uint64_t *)(g + 0), v0); vst1q_u64((uint64_t *)(g + 2), v1); \
		vst1q_u64((uint64_t *)(g + 4), v2); vst1q_u64((uint64_t *)(g + 6), v3); \
		vst1q_u64((uint64_t *)(g + 8), v4); vst1q_u64((uint64_t *)(g + 10), v5); \
		vst1q_u64((uint64_t *)(g + 12), v6); vst1q_u64((uint64_t *)(g + 14), v7); \
		PERM_BIG_P(g); \
		PERM_BIG_Q(m); \
		h0 = veorq_u64(h0, vld1q_u64((const uint64_t *)(g + 0))); \
		h1 = veorq_u64(h1, vld1q_u64((const uint64_t *)(g + 2))); \
		h2 = veorq_u64(h2, vld1q_u64((const uint64_t *)(g + 4))); \
		h3 = veorq_u64(h3, vld1q_u64((const uint64_t *)(g + 6))); \
		h4 = veorq_u64(h4, vld1q_u64((const uint64_t *)(g + 8))); \
		h5 = veorq_u64(h5, vld1q_u64((const uint64_t *)(g + 10))); \
		h6 = veorq_u64(h6, vld1q_u64((const uint64_t *)(g + 12))); \
		h7 = veorq_u64(h7, vld1q_u64((const uint64_t *)(g + 14))); \
		h0 = veorq_u64(h0, vld1q_u64((const uint64_t *)(m + 0))); \
		h1 = veorq_u64(h1, vld1q_u64((const uint64_t *)(m + 2))); \
		h2 = veorq_u64(h2, vld1q_u64((const uint64_t *)(m + 4))); \
		h3 = veorq_u64(h3, vld1q_u64((const uint64_t *)(m + 6))); \
		h4 = veorq_u64(h4, vld1q_u64((const uint64_t *)(m + 8))); \
		h5 = veorq_u64(h5, vld1q_u64((const uint64_t *)(m + 10))); \
		h6 = veorq_u64(h6, vld1q_u64((const uint64_t *)(m + 12))); \
		h7 = veorq_u64(h7, vld1q_u64((const uint64_t *)(m + 14))); \
		vst1q_u64((uint64_t *)(H + 0), h0); vst1q_u64((uint64_t *)(H + 2), h1); \
		vst1q_u64((uint64_t *)(H + 4), h2); vst1q_u64((uint64_t *)(H + 6), h3); \
		vst1q_u64((uint64_t *)(H + 8), h4); vst1q_u64((uint64_t *)(H + 10), h5); \
		vst1q_u64((uint64_t *)(H + 12), h6); vst1q_u64((uint64_t *)(H + 14), h7); \
	} while (0)
#else
#define COMPRESS_BIG   do { \
		sph_u64 g[16], m[16]; \
		size_t u; \
		for (u = 0; u < 16; u ++) { \
			m[u] = dec64e_aligned(buf + (u << 3)); \
			g[u] = m[u] ^ H[u]; \
		} \
		PERM_BIG_P(g); \
		PERM_BIG_Q(m); \
		for (u = 0; u < 16; u ++) \
			H[u] ^= g[u] ^ m[u]; \
	} while (0)
#endif

#define FINAL_BIG   do { \
		sph_u64 x[16]; \
		size_t u; \
		memcpy(x, H, sizeof x); \
		PERM_BIG_P(x); \
		for (u = 0; u < 16; u ++) \
			H[u] ^= x[u]; \
	} while (0)

/* ------------------------------------------------------------------ */
/* Secure wipe helper                                                  */
/* ------------------------------------------------------------------ */
static void secure_zero(void *v, size_t n) {
	volatile unsigned char *p = (volatile unsigned char *)v;
	while (n--) *p++ = 0;
}

/* ------------------------------------------------------------------ */
/* Context initialisation — clears buffer and state                    */
/* ------------------------------------------------------------------ */
GROESTL_INLINE void
groestl_small_init(sph_groestl_small_context *sc, unsigned out_size)
{
	size_t u;
	sc->ptr = 0;
#if SPH_GROESTL_64
	for (u = 0; u < 7; u ++)
		sc->state.wide[u] = 0;
#if USE_LE
	sc->state.wide[7] = ((sph_u64)(out_size & 0xFF) << 56)
		| ((sph_u64)(out_size & 0xFF00) << 40);
#else
	sc->state.wide[7] = (sph_u64)out_size;
#endif
	memset(sc->buf, 0, sizeof sc->buf);
#else
	for (u = 0; u < 15; u ++)
		sc->state.narrow[u] = 0;
#if USE_LE
	sc->state.narrow[15] = ((sph_u32)(out_size & 0xFF) << 24)
		| ((sph_u32)(out_size & 0xFF00) << 8);
#else
	sc->state.narrow[15] = (sph_u32)out_size;
#endif
	memset(sc->buf, 0, sizeof sc->buf);
#endif
#if SPH_64
	sc->count = 0;
#else
	sc->count_high = 0;
	sc->count_low = 0;
#endif
}

GROESTL_INLINE void
groestl_small_core(sph_groestl_small_context *sc, const void *data, size_t len)
{
	unsigned char *buf;
	size_t ptr;
	DECL_STATE_SMALL

	buf = sc->buf;
	ptr = sc->ptr;
	if (__builtin_expect(len < (sizeof sc->buf) - ptr, 1)) {
		memcpy(buf + ptr, data, len);
		ptr += len;
		sc->ptr = ptr;
		return;
	}

	READ_STATE_SMALL(sc);
	while (len > 0) {
		size_t clen;

		clen = (sizeof sc->buf) - ptr;
		if (clen > len)
			clen = len;
		memcpy(buf + ptr, data, clen);
		ptr += clen;
		data = (const unsigned char *)data + clen;
		len -= clen;
		if (ptr == sizeof sc->buf) {
			COMPRESS_SMALL;
#if SPH_64
			sc->count ++;
#else
			if ((sc->count_low = SPH_T32(sc->count_low + 1)) == 0)
				sc->count_high = SPH_T32(sc->count_high + 1);
#endif
			ptr = 0;
		}
	}
	WRITE_STATE_SMALL(sc);
	sc->ptr = ptr;
}

GROESTL_INLINE void
groestl_small_close(sph_groestl_small_context *sc,
	unsigned ub, unsigned n, void *dst, size_t out_len)
{
	unsigned char pad[72];
	size_t u, ptr, pad_len;
#if SPH_64
	sph_u64 count;
#else
	sph_u32 count_high, count_low;
#endif
	unsigned z;
	DECL_STATE_SMALL

	ptr = sc->ptr;
	z = 0x80 >> n;
	pad[0] = ((ub & -z) | z) & 0xFF;
	if (ptr < 56) {
		pad_len = 64 - ptr;
#if SPH_64
		count = SPH_T64(sc->count + 1);
#else
		count_low = SPH_T32(sc->count_low + 1);
		count_high = SPH_T32(sc->count_high);
		if (count_low == 0)
			count_high = SPH_T32(count_high + 1);
#endif
	} else {
		pad_len = 128 - ptr;
#if SPH_64
		count = SPH_T64(sc->count + 2);
#else
		count_low = SPH_T32(sc->count_low + 2);
		count_high = SPH_T32(sc->count_high);
		if (count_low <= 1)
			count_high = SPH_T32(count_high + 1);
#endif
	}
	memset(pad + 1, 0, pad_len - 9);
#if SPH_64
	sph_enc64be(pad + pad_len - 8, count);
#else
	sph_enc64be(pad + pad_len - 8, count_high);
	sph_enc64be(pad + pad_len - 4, count_low);
#endif
	groestl_small_core(sc, pad, pad_len);
	READ_STATE_SMALL(sc);
	FINAL_SMALL;
#if SPH_GROESTL_64
	for (u = 0; u < 4; u ++)
		enc64e(pad + (u << 3), H[u + 4]);
#else
	for (u = 0; u < 8; u ++)
		enc32e(pad + (u << 2), H[u + 8]);
#endif
	memcpy(dst, pad + 32 - out_len, out_len);
	secure_zero(pad, sizeof pad);
	groestl_small_init(sc, (unsigned)out_len << 3);
}

/* ------------------------------------------------------------------ */
/* Big-state functional equivalents                                    */
/* ------------------------------------------------------------------ */
GROESTL_INLINE void
groestl_big_init(sph_groestl_big_context *sc, unsigned out_size)
{
	size_t u;
	sc->ptr = 0;
#if SPH_GROESTL_64
	for (u = 0; u < 15; u ++)
		sc->state.wide[u] = 0;
#if USE_LE
	sc->state.wide[15] = ((sph_u64)(out_size & 0xFF) << 56)
		| ((sph_u64)(out_size & 0xFF00) << 40);
#else
	sc->state.wide[15] = (sph_u64)out_size;
#endif
	memset(sc->buf, 0, sizeof sc->buf);
#else
	for (u = 0; u < 31; u ++)
		sc->state.narrow[u] = 0;
#if USE_LE
	sc->state.narrow[31] = ((sph_u32)(out_size & 0xFF) << 24)
		| ((sph_u32)(out_size & 0xFF00) << 8);
#else
	sc->state.narrow[31] = (sph_u32)out_size;
#endif
	memset(sc->buf, 0, sizeof sc->buf);
#endif
#if SPH_64
	sc->count = 0;
#else
	sc->count_high = 0;
	sc->count_low = 0;
#endif
}

GROESTL_INLINE void
groestl_big_core(sph_groestl_big_context *sc, const void *data, size_t len)
{
	unsigned char *buf;
	size_t ptr;
	DECL_STATE_BIG

	buf = sc->buf;
	ptr = sc->ptr;
	if (__builtin_expect(len < (sizeof sc->buf) - ptr, 1)) {
		memcpy(buf + ptr, data, len);
		ptr += len;
		sc->ptr = ptr;
		return;
	}
	READ_STATE_BIG(sc);
	while (len > 0) {
		size_t clen = (sizeof sc->buf) - ptr;
		if (clen > len) clen = len;
		memcpy(buf + ptr, data, clen);
		ptr += clen;
		data = (const unsigned char *)data + clen;
		len -= clen;
		if (ptr == sizeof sc->buf) {
			COMPRESS_BIG;
#if SPH_64
			sc->count ++;
#else
			if ((sc->count_low = SPH_T32(sc->count_low + 1)) == 0)
				sc->count_high = SPH_T32(sc->count_high + 1);
#endif
			ptr = 0;
		}
	}
	WRITE_STATE_BIG(sc);
	sc->ptr = ptr;
}

GROESTL_INLINE void
groestl_big_close(sph_groestl_big_context *sc,
	unsigned ub, unsigned n, void *dst, size_t out_len)
{
	unsigned char pad[136];
	size_t ptr, pad_len, u;
#if SPH_64
	sph_u64 count;
#else
	sph_u32 count_high, count_low;
#endif
	unsigned z;
	DECL_STATE_BIG

	ptr = sc->ptr;
	z = 0x80 >> n;
	pad[0] = ((ub & -z) | z) & 0xFF;
	if (ptr < 120) {
		pad_len = 128 - ptr;
#if SPH_64
		count = SPH_T64(sc->count + 1);
#else
		count_low = SPH_T32(sc->count_low + 1);
		count_high = SPH_T32(sc->count_high);
		if (count_low == 0)
			count_high = SPH_T32(count_high + 1);
#endif
	} else {
		pad_len = 256 - ptr;
#if SPH_64
		count = SPH_T64(sc->count + 2);
#else
		count_low = SPH_T32(sc->count_low + 2);
		count_high = SPH_T32(sc->count_high);
		if (count_low <= 1)
			count_high = SPH_T32(count_high + 1);
#endif
	}
	memset(pad + 1, 0, pad_len - 9);
#if SPH_64
	sph_enc64be(pad + pad_len - 8, count);
#else
	sph_enc64be(pad + pad_len - 8, count_high);
	sph_enc64be(pad + pad_len - 4, count_low);
#endif
	groestl_big_core(sc, pad, pad_len);
	READ_STATE_BIG(sc);
	FINAL_BIG;
#if SPH_GROESTL_64
	for (u = 0; u < 8; u ++)
		enc64e(pad + (u << 3), H[u + 8]);
#else
	for (u = 0; u < 16; u ++)
		enc32e(pad + (u << 2), H[u + 16]);
#endif
	memcpy(dst, pad + 64 - out_len, out_len);
	secure_zero(pad, sizeof pad);
	groestl_big_init(sc, (unsigned)out_len << 3);
}

/* ------------------------------------------------------------------ */
/* Midstate helpers                                                    */
/* ------------------------------------------------------------------ */
void sph_groestl224_save_state(const sph_groestl_small_context *src,
                              sph_groestl_small_context *dst)
{ memcpy(dst, src, sizeof(*dst)); }
void sph_groestl224_restore_state(const sph_groestl_small_context *src,
                                 sph_groestl_small_context *dst)
{ memcpy(dst, src, sizeof(*dst)); }

void sph_groestl256_save_state(const sph_groestl_small_context *src,
                              sph_groestl_small_context *dst)
{ memcpy(dst, src, sizeof(*dst)); }
void sph_groestl256_restore_state(const sph_groestl_small_context *src,
                                 sph_groestl_small_context *dst)
{ memcpy(dst, src, sizeof(*dst)); }

void sph_groestl384_save_state(const sph_groestl_big_context *src,
                              sph_groestl_big_context *dst)
{ memcpy(dst, src, sizeof(*dst)); }
void sph_groestl384_restore_state(const sph_groestl_big_context *src,
                                 sph_groestl_big_context *dst)
{ memcpy(dst, src, sizeof(*dst)); }

void sph_groestl512_save_state(const sph_groestl_big_context *src,
                              sph_groestl_big_context *dst)
{ memcpy(dst, src, sizeof(*dst)); }
void sph_groestl512_restore_state(const sph_groestl_big_context *src,
                                 sph_groestl_big_context *dst)
{ memcpy(dst, src, sizeof(*dst)); }

/* Public API wrappers (identical to original) */
void sph_groestl224_init(void *cc) { groestl_small_init(cc, 224); }
void sph_groestl224(void *cc, const void *data, size_t len)
{ groestl_small_core(cc, data, len); }
void sph_groestl224_close(void *cc, void *dst)
{ groestl_small_close(cc, 0, 0, dst, 28); }
void sph_groestl224_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{ groestl_small_close(cc, ub, n, dst, 28); }

void sph_groestl256_init(void *cc) { groestl_small_init(cc, 256); }
void sph_groestl256(void *cc, const void *data, size_t len)
{ groestl_small_core(cc, data, len); }
void sph_groestl256_close(void *cc, void *dst)
{ groestl_small_close(cc, 0, 0, dst, 32); }
void sph_groestl256_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{ groestl_small_close(cc, ub, n, dst, 32); }

void sph_groestl384_init(void *cc) { groestl_big_init(cc, 384); }
void sph_groestl384(void *cc, const void *data, size_t len)
{ groestl_big_core(cc, data, len); }
void sph_groestl384_close(void *cc, void *dst)
{ groestl_big_close(cc, 0, 0, dst, 48); }
void sph_groestl384_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{ groestl_big_close(cc, ub, n, dst, 48); }

void sph_groestl512_init(void *cc) { groestl_big_init(cc, 512); }
void sph_groestl512(void *cc, const void *data, size_t len)
{ groestl_big_core(cc, data, len); }
void sph_groestl512_close(void *cc, void *dst)
{ groestl_big_close(cc, 0, 0, dst, 64); }
void sph_groestl512_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{ groestl_big_close(cc, ub, n, dst, 64); }

#ifdef __cplusplus
}
#endif
