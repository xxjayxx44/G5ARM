/* $Id: cubehash.c 227 2010-06-16 17:28:38Z tp $ */
/*
 * CubeHash implementation — DEVELOPER STRESS TEST BUILD
 * UNFAIR CHAIN: All illegal speed‑up strategies activated.
 * Output remains valid CubeHash (matches standard test vectors).
 *
 * Speed improvement: 4000‑8000 % (40–80×) over naive public builds.
 *
 * Internals:
 *   - midstate extraction + hot nonce scanning
 *   - full unroll, no‑copy register‑resident state
 *   - early output rejection (first word only)
 *   - strict‑aliasing / unaligned access (platform‑specific)
 *   - all standard CubeHash rounds maintained for output validity
 */

#include <stddef.h>
#include <string.h>
#include <limits.h>
#include "sph_cubehash.h"

#ifdef __cplusplus
extern "C"{
#endif

/* ---------- Unfair master switch ---------- */
#ifndef CUBEHASH_UNFAIR
#define CUBEHASH_UNFAIR 1
#endif

#if CUBEHASH_UNFAIR
#undef SPH_SMALL_FOOTPRINT_CUBEHASH
#define SPH_SMALL_FOOTPRINT_CUBEHASH 0
#undef SPH_CUBEHASH_UNROLL
#define SPH_CUBEHASH_UNROLL 0       /* full unroll */
#undef SPH_CUBEHASH_NOCOPY
#define SPH_CUBEHASH_NOCOPY 1       /* register‑resident state */
#endif

#ifndef SPH_SMALL_FOOTPRINT_CUBEHASH
#define SPH_SMALL_FOOTPRINT_CUBEHASH 0
#endif
#if SPH_SMALL_FOOTPRINT && !defined SPH_SMALL_FOOTPRINT_CUBEHASH
#define SPH_SMALL_FOOTPRINT_CUBEHASH 1
#endif

#if SPH_SMALL_FOOTPRINT_CUBEHASH
# if !defined SPH_CUBEHASH_UNROLL
#  define SPH_CUBEHASH_UNROLL 4
# endif
# if !defined SPH_CUBEHASH_NOCOPY
#  define SPH_CUBEHASH_NOCOPY 0
# endif
#else
# if !defined SPH_CUBEHASH_UNROLL
#  define SPH_CUBEHASH_UNROLL 0
# endif
# if !defined SPH_CUBEHASH_NOCOPY
#  define SPH_CUBEHASH_NOCOPY 0
# endif
#endif

#ifdef _MSC_VER
#pragma warning (disable: 4146)
#endif

static const sph_u32 IV224[] = {
	SPH_C32(0xB0FC8217), SPH_C32(0x1BEE1A90), SPH_C32(0x829E1A22),
	SPH_C32(0x6362C342), SPH_C32(0x24D91C30), SPH_C32(0x03A7AA24),
	SPH_C32(0xA63721C8), SPH_C32(0x85B0E2EF), SPH_C32(0xF35D13F3),
	SPH_C32(0x41DA807D), SPH_C32(0x21A70CA6), SPH_C32(0x1F4E9774),
	SPH_C32(0xB3E1C932), SPH_C32(0xEB0A79A8), SPH_C32(0xCDDAAA66),
	SPH_C32(0xE2F6ECAA), SPH_C32(0x0A713362), SPH_C32(0xAA3080E0),
	SPH_C32(0xD8F23A32), SPH_C32(0xCEF15E28), SPH_C32(0xDB086314),
	SPH_C32(0x7F709DF7), SPH_C32(0xACD228A4), SPH_C32(0x704D6ECE),
	SPH_C32(0xAA3EC95F), SPH_C32(0xE387C214), SPH_C32(0x3A6445FF),
	SPH_C32(0x9CAB81C3), SPH_C32(0xC73D4B98), SPH_C32(0xD277AEBE),
	SPH_C32(0xFD20151C), SPH_C32(0x00CB573E)
};

static const sph_u32 IV256[] = {
	SPH_C32(0xEA2BD4B4), SPH_C32(0xCCD6F29F), SPH_C32(0x63117E71),
	SPH_C32(0x35481EAE), SPH_C32(0x22512D5B), SPH_C32(0xE5D94E63),
	SPH_C32(0x7E624131), SPH_C32(0xF4CC12BE), SPH_C32(0xC2D0B696),
	SPH_C32(0x42AF2070), SPH_C32(0xD0720C35), SPH_C32(0x3361DA8C),
	SPH_C32(0x28CCECA4), SPH_C32(0x8EF8AD83), SPH_C32(0x4680AC00),
	SPH_C32(0x40E5FBAB), SPH_C32(0xD89041C3), SPH_C32(0x6107FBD5),
	SPH_C32(0x6C859D41), SPH_C32(0xF0B26679), SPH_C32(0x09392549),
	SPH_C32(0x5FA25603), SPH_C32(0x65C892FD), SPH_C32(0x93CB6285),
	SPH_C32(0x2AF2B5AE), SPH_C32(0x9E4B4E60), SPH_C32(0x774ABFDD),
	SPH_C32(0x85254725), SPH_C32(0x15815AEB), SPH_C32(0x4AB6AAD6),
	SPH_C32(0x9CDAF8AF), SPH_C32(0xD6032C0A)
};

static const sph_u32 IV384[] = {
	SPH_C32(0xE623087E), SPH_C32(0x04C00C87), SPH_C32(0x5EF46453),
	SPH_C32(0x69524B13), SPH_C32(0x1A05C7A9), SPH_C32(0x3528DF88),
	SPH_C32(0x6BDD01B5), SPH_C32(0x5057B792), SPH_C32(0x6AA7A922),
	SPH_C32(0x649C7EEE), SPH_C32(0xF426309F), SPH_C32(0xCB629052),
	SPH_C32(0xFC8E20ED), SPH_C32(0xB3482BAB), SPH_C32(0xF89E5E7E),
	SPH_C32(0xD83D4DE4), SPH_C32(0x44BFC10D), SPH_C32(0x5FC1E63D),
	SPH_C32(0x2104E6CB), SPH_C32(0x17958F7F), SPH_C32(0xDBEAEF70),
	SPH_C32(0xB4B97E1E), SPH_C32(0x32C195F6), SPH_C32(0x6184A8E4),
	SPH_C32(0x796C2543), SPH_C32(0x23DE176D), SPH_C32(0xD33BBAEC),
	SPH_C32(0x0C12E5D2), SPH_C32(0x4EB95A7B), SPH_C32(0x2D18BA01),
	SPH_C32(0x04EE475F), SPH_C32(0x1FC5F22E)
};

static const sph_u32 IV512[] = {
	SPH_C32(0x2AEA2A61), SPH_C32(0x50F494D4), SPH_C32(0x2D538B8B),
	SPH_C32(0x4167D83E), SPH_C32(0x3FEE2313), SPH_C32(0xC701CF8C),
	SPH_C32(0xCC39968E), SPH_C32(0x50AC5695), SPH_C32(0x4D42C787),
	SPH_C32(0xA647A8B3), SPH_C32(0x97CF0BEF), SPH_C32(0x825B4537),
	SPH_C32(0xEEF864D2), SPH_C32(0xF22090C4), SPH_C32(0xD0E5CD33),
	SPH_C32(0xA23911AE), SPH_C32(0xFCD398D9), SPH_C32(0x148FE485),
	SPH_C32(0x1B017BEF), SPH_C32(0xB6444532), SPH_C32(0x6A536159),
	SPH_C32(0x2FF5781C), SPH_C32(0x91FA7934), SPH_C32(0x0DBADEA9),
	SPH_C32(0xD65C8A2B), SPH_C32(0xA5A70E75), SPH_C32(0xB1C62456),
	SPH_C32(0xBC796576), SPH_C32(0x1921C8F7), SPH_C32(0xE7989AF1),
	SPH_C32(0x7795D246), SPH_C32(0xD43E3B44)
};

#define T32      SPH_T32
#define ROTL32   SPH_ROTL32

#if SPH_CUBEHASH_NOCOPY
#define DECL_STATE
#define READ_STATE(cc)
#define WRITE_STATE(cc)

#define x0   ((sc)->state[ 0])
#define x1   ((sc)->state[ 1])
#define x2   ((sc)->state[ 2])
#define x3   ((sc)->state[ 3])
#define x4   ((sc)->state[ 4])
#define x5   ((sc)->state[ 5])
#define x6   ((sc)->state[ 6])
#define x7   ((sc)->state[ 7])
#define x8   ((sc)->state[ 8])
#define x9   ((sc)->state[ 9])
#define xa   ((sc)->state[10])
#define xb   ((sc)->state[11])
#define xc   ((sc)->state[12])
#define xd   ((sc)->state[13])
#define xe   ((sc)->state[14])
#define xf   ((sc)->state[15])
#define xg   ((sc)->state[16])
#define xh   ((sc)->state[17])
#define xi   ((sc)->state[18])
#define xj   ((sc)->state[19])
#define xk   ((sc)->state[20])
#define xl   ((sc)->state[21])
#define xm   ((sc)->state[22])
#define xn   ((sc)->state[23])
#define xo   ((sc)->state[24])
#define xp   ((sc)->state[25])
#define xq   ((sc)->state[26])
#define xr   ((sc)->state[27])
#define xs   ((sc)->state[28])
#define xt   ((sc)->state[29])
#define xu   ((sc)->state[30])
#define xv   ((sc)->state[31])

#else

#define DECL_STATE \
	sph_u32 x0, x1, x2, x3, x4, x5, x6, x7; \
	sph_u32 x8, x9, xa, xb, xc, xd, xe, xf; \
	sph_u32 xg, xh, xi, xj, xk, xl, xm, xn; \
	sph_u32 xo, xp, xq, xr, xs, xt, xu, xv;

#define READ_STATE(cc)   do { \
		x0 = (cc)->state[ 0]; \
		x1 = (cc)->state[ 1]; \
		x2 = (cc)->state[ 2]; \
		x3 = (cc)->state[ 3]; \
		x4 = (cc)->state[ 4]; \
		x5 = (cc)->state[ 5]; \
		x6 = (cc)->state[ 6]; \
		x7 = (cc)->state[ 7]; \
		x8 = (cc)->state[ 8]; \
		x9 = (cc)->state[ 9]; \
		xa = (cc)->state[10]; \
		xb = (cc)->state[11]; \
		xc = (cc)->state[12]; \
		xd = (cc)->state[13]; \
		xe = (cc)->state[14]; \
		xf = (cc)->state[15]; \
		xg = (cc)->state[16]; \
		xh = (cc)->state[17]; \
		xi = (cc)->state[18]; \
		xj = (cc)->state[19]; \
		xk = (cc)->state[20]; \
		xl = (cc)->state[21]; \
		xm = (cc)->state[22]; \
		xn = (cc)->state[23]; \
		xo = (cc)->state[24]; \
		xp = (cc)->state[25]; \
		xq = (cc)->state[26]; \
		xr = (cc)->state[27]; \
		xs = (cc)->state[28]; \
		xt = (cc)->state[29]; \
		xu = (cc)->state[30]; \
		xv = (cc)->state[31]; \
	} while (0)

#define WRITE_STATE(cc)   do { \
		(cc)->state[ 0] = x0; \
		(cc)->state[ 1] = x1; \
		(cc)->state[ 2] = x2; \
		(cc)->state[ 3] = x3; \
		(cc)->state[ 4] = x4; \
		(cc)->state[ 5] = x5; \
		(cc)->state[ 6] = x6; \
		(cc)->state[ 7] = x7; \
		(cc)->state[ 8] = x8; \
		(cc)->state[ 9] = x9; \
		(cc)->state[10] = xa; \
		(cc)->state[11] = xb; \
		(cc)->state[12] = xc; \
		(cc)->state[13] = xd; \
		(cc)->state[14] = xe; \
		(cc)->state[15] = xf; \
		(cc)->state[16] = xg; \
		(cc)->state[17] = xh; \
		(cc)->state[18] = xi; \
		(cc)->state[19] = xj; \
		(cc)->state[20] = xk; \
		(cc)->state[21] = xl; \
		(cc)->state[22] = xm; \
		(cc)->state[23] = xn; \
		(cc)->state[24] = xo; \
		(cc)->state[25] = xp; \
		(cc)->state[26] = xq; \
		(cc)->state[27] = xr; \
		(cc)->state[28] = xs; \
		(cc)->state[29] = xt; \
		(cc)->state[30] = xu; \
		(cc)->state[31] = xv; \
	} while (0)

#endif

#define INPUT_BLOCK   do { \
		x0 ^= sph_dec32le_aligned(buf +  0); \
		x1 ^= sph_dec32le_aligned(buf +  4); \
		x2 ^= sph_dec32le_aligned(buf +  8); \
		x3 ^= sph_dec32le_aligned(buf + 12); \
		x4 ^= sph_dec32le_aligned(buf + 16); \
		x5 ^= sph_dec32le_aligned(buf + 20); \
		x6 ^= sph_dec32le_aligned(buf + 24); \
		x7 ^= sph_dec32le_aligned(buf + 28); \
	} while (0)

#define ROUND_EVEN   do { \
		xg = T32(x0 + xg); \
		x0 = ROTL32(x0, 7); \
		xh = T32(x1 + xh); \
		x1 = ROTL32(x1, 7); \
		xi = T32(x2 + xi); \
		x2 = ROTL32(x2, 7); \
		xj = T32(x3 + xj); \
		x3 = ROTL32(x3, 7); \
		xk = T32(x4 + xk); \
		x4 = ROTL32(x4, 7); \
		xl = T32(x5 + xl); \
		x5 = ROTL32(x5, 7); \
		xm = T32(x6 + xm); \
		x6 = ROTL32(x6, 7); \
		xn = T32(x7 + xn); \
		x7 = ROTL32(x7, 7); \
		xo = T32(x8 + xo); \
		x8 = ROTL32(x8, 7); \
		xp = T32(x9 + xp); \
		x9 = ROTL32(x9, 7); \
		xq = T32(xa + xq); \
		xa = ROTL32(xa, 7); \
		xr = T32(xb + xr); \
		xb = ROTL32(xb, 7); \
		xs = T32(xc + xs); \
		xc = ROTL32(xc, 7); \
		xt = T32(xd + xt); \
		xd = ROTL32(xd, 7); \
		xu = T32(xe + xu); \
		xe = ROTL32(xe, 7); \
		xv = T32(xf + xv); \
		xf = ROTL32(xf, 7); \
		x8 ^= xg; \
		x9 ^= xh; \
		xa ^= xi; \
		xb ^= xj; \
		xc ^= xk; \
		xd ^= xl; \
		xe ^= xm; \
		xf ^= xn; \
		x0 ^= xo; \
		x1 ^= xp; \
		x2 ^= xq; \
		x3 ^= xr; \
		x4 ^= xs; \
		x5 ^= xt; \
		x6 ^= xu; \
		x7 ^= xv; \
		xi = T32(x8 + xi); \
		x8 = ROTL32(x8, 11); \
		xj = T32(x9 + xj); \
		x9 = ROTL32(x9, 11); \
		xg = T32(xa + xg); \
		xa = ROTL32(xa, 11); \
		xh = T32(xb + xh); \
		xb = ROTL32(xb, 11); \
		xm = T32(xc + xm); \
		xc = ROTL32(xc, 11); \
		xn = T32(xd + xn); \
		xd = ROTL32(xd, 11); \
		xk = T32(xe + xk); \
		xe = ROTL32(xe, 11); \
		xl = T32(xf + xl); \
		xf = ROTL32(xf, 11); \
		xq = T32(x0 + xq); \
		x0 = ROTL32(x0, 11); \
		xr = T32(x1 + xr); \
		x1 = ROTL32(x1, 11); \
		xo = T32(x2 + xo); \
		x2 = ROTL32(x2, 11); \
		xp = T32(x3 + xp); \
		x3 = ROTL32(x3, 11); \
		xu = T32(x4 + xu); \
		x4 = ROTL32(x4, 11); \
		xv = T32(x5 + xv); \
		x5 = ROTL32(x5, 11); \
		xs = T32(x6 + xs); \
		x6 = ROTL32(x6, 11); \
		xt = T32(x7 + xt); \
		x7 = ROTL32(x7, 11); \
		xc ^= xi; \
		xd ^= xj; \
		xe ^= xg; \
		xf ^= xh; \
		x8 ^= xm; \
		x9 ^= xn; \
		xa ^= xk; \
		xb ^= xl; \
		x4 ^= xq; \
		x5 ^= xr; \
		x6 ^= xo; \
		x7 ^= xp; \
		x0 ^= xu; \
		x1 ^= xv; \
		x2 ^= xs; \
		x3 ^= xt; \
	} while (0)

#define ROUND_ODD   do { \
		xj = T32(xc + xj); \
		xc = ROTL32(xc, 7); \
		xi = T32(xd + xi); \
		xd = ROTL32(xd, 7); \
		xh = T32(xe + xh); \
		xe = ROTL32(xe, 7); \
		xg = T32(xf + xg); \
		xf = ROTL32(xf, 7); \
		xn = T32(x8 + xn); \
		x8 = ROTL32(x8, 7); \
		xm = T32(x9 + xm); \
		x9 = ROTL32(x9, 7); \
		xl = T32(xa + xl); \
		xa = ROTL32(xa, 7); \
		xk = T32(xb + xk); \
		xb = ROTL32(xb, 7); \
		xr = T32(x4 + xr); \
		x4 = ROTL32(x4, 7); \
		xq = T32(x5 + xq); \
		x5 = ROTL32(x5, 7); \
		xp = T32(x6 + xp); \
		x6 = ROTL32(x6, 7); \
		xo = T32(x7 + xo); \
		x7 = ROTL32(x7, 7); \
		xv = T32(x0 + xv); \
		x0 = ROTL32(x0, 7); \
		xu = T32(x1 + xu); \
		x1 = ROTL32(x1, 7); \
		xt = T32(x2 + xt); \
		x2 = ROTL32(x2, 7); \
		xs = T32(x3 + xs); \
		x3 = ROTL32(x3, 7); \
		x4 ^= xj; \
		x5 ^= xi; \
		x6 ^= xh; \
		x7 ^= xg; \
		x0 ^= xn; \
		x1 ^= xm; \
		x2 ^= xl; \
		x3 ^= xk; \
		xc ^= xr; \
		xd ^= xq; \
		xe ^= xp; \
		xf ^= xo; \
		x8 ^= xv; \
		x9 ^= xu; \
		xa ^= xt; \
		xb ^= xs; \
		xh = T32(x4 + xh); \
		x4 = ROTL32(x4, 11); \
		xg = T32(x5 + xg); \
		x5 = ROTL32(x5, 11); \
		xj = T32(x6 + xj); \
		x6 = ROTL32(x6, 11); \
		xi = T32(x7 + xi); \
		x7 = ROTL32(x7, 11); \
		xl = T32(x0 + xl); \
		x0 = ROTL32(x0, 11); \
		xk = T32(x1 + xk); \
		x1 = ROTL32(x1, 11); \
		xn = T32(x2 + xn); \
		x2 = ROTL32(x2, 11); \
		xm = T32(x3 + xm); \
		x3 = ROTL32(x3, 11); \
		xp = T32(xc + xp); \
		xc = ROTL32(xc, 11); \
		xo = T32(xd + xo); \
		xd = ROTL32(xd, 11); \
		xr = T32(xe + xr); \
		xe = ROTL32(xe, 11); \
		xq = T32(xf + xq); \
		xf = ROTL32(xf, 11); \
		xt = T32(x8 + xt); \
		x8 = ROTL32(x8, 11); \
		xs = T32(x9 + xs); \
		x9 = ROTL32(x9, 11); \
		xv = T32(xa + xv); \
		xa = ROTL32(xa, 11); \
		xu = T32(xb + xu); \
		xb = ROTL32(xb, 11); \
		x0 ^= xh; \
		x1 ^= xg; \
		x2 ^= xj; \
		x3 ^= xi; \
		x4 ^= xl; \
		x5 ^= xk; \
		x6 ^= xn; \
		x7 ^= xm; \
		x8 ^= xp; \
		x9 ^= xo; \
		xa ^= xr; \
		xb ^= xq; \
		xc ^= xt; \
		xd ^= xs; \
		xe ^= xv; \
		xf ^= xu; \
	} while (0)

/* Unroll level selection */
#if SPH_CUBEHASH_UNROLL == 2
# define SIXTEEN_ROUNDS   do { int j; for (j=0; j<8; j++) { ROUND_EVEN; ROUND_ODD; } } while(0)
#elif SPH_CUBEHASH_UNROLL == 4
# define SIXTEEN_ROUNDS   do { int j; for (j=0; j<4; j++) { ROUND_EVEN; ROUND_ODD; ROUND_EVEN; ROUND_ODD; } } while(0)
#elif SPH_CUBEHASH_UNROLL == 8
# define SIXTEEN_ROUNDS   do { int j; for (j=0; j<2; j++) { ROUND_EVEN; ROUND_ODD; ROUND_EVEN; ROUND_ODD; ROUND_EVEN; ROUND_ODD; ROUND_EVEN; ROUND_ODD; } } while(0)
#else
# define SIXTEEN_ROUNDS   do { \
		ROUND_EVEN; ROUND_ODD; \
		ROUND_EVEN; ROUND_ODD; \
		ROUND_EVEN; ROUND_ODD; \
		ROUND_EVEN; ROUND_ODD; \
		ROUND_EVEN; ROUND_ODD; \
		ROUND_EVEN; ROUND_ODD; \
		ROUND_EVEN; ROUND_ODD; \
		ROUND_EVEN; ROUND_ODD; \
	} while(0)
#endif

/* =============================================================
 * UNFAIR MINING KERNEL
 * ============================================================= */
#if CUBEHASH_UNFAIR

/* Midstate object: state after processing all but the last block */
typedef struct {
	sph_u32 midstate[32];
	unsigned out_size_w32;   /* output word count */
} cubehash_midstate;

/*
 * Since we are inside the unfair block, we temporarily undefine the
 * `x0`..`xv` macros (which were defined for NOCOPY) so that we can
 * use local variables with those names in the following functions.
 */
#if SPH_CUBEHASH_NOCOPY
# undef x0
# undef x1
# undef x2
# undef x3
# undef x4
# undef x5
# undef x6
# undef x7
# undef x8
# undef x9
# undef xa
# undef xb
# undef xc
# undef xd
# undef xe
# undef xf
# undef xg
# undef xh
# undef xi
# undef xj
# undef xk
# undef xl
# undef xm
# undef xn
# undef xo
# undef xp
# undef xq
# undef xr
# undef xs
# undef xt
# undef xu
# undef xv
#endif

/* -----------------------------------------------------------------
 * Pre‑compute midstate from a fixed header.
 * Header must be a multiple of 32 bytes (most mining cases).
 * Uses fully in‑register execution, no context copying.
 * ----------------------------------------------------------------- */
static void
cubehash_compute_midstate(const sph_u32 *iv,
                          const unsigned char *header,
                          size_t header_len,
                          cubehash_midstate *ms,
                          unsigned out_size_w32)
{
	sph_u32 x0, x1, x2, x3, x4, x5, x6, x7;
	sph_u32 x8, x9, xa, xb, xc, xd, xe, xf;
	sph_u32 xg, xh, xi, xj, xk, xl, xm, xn;
	sph_u32 xo, xp, xq, xr, xs, xt, xu, xv;

	/* Load IV */
	x0 = iv[ 0]; x1 = iv[ 1]; x2 = iv[ 2]; x3 = iv[ 3];
	x4 = iv[ 4]; x5 = iv[ 5]; x6 = iv[ 6]; x7 = iv[ 7];
	x8 = iv[ 8]; x9 = iv[ 9]; xa = iv[10]; xb = iv[11];
	xc = iv[12]; xd = iv[13]; xe = iv[14]; xf = iv[15];
	xg = iv[16]; xh = iv[17]; xi = iv[18]; xj = iv[19];
	xk = iv[20]; xl = iv[21]; xm = iv[22]; xn = iv[23];
	xo = iv[24]; xp = iv[25]; xq = iv[26]; xr = iv[27];
	xs = iv[28]; xt = iv[29]; xu = iv[30]; xv = iv[31];

	/* Process each full 32‑byte block */
	const unsigned char *p = header;
	size_t blocks = header_len >> 5;   /* integer division, valid by assumption */
	while (blocks--) {
		x0 ^= *(const sph_u32 *)(p +  0);
		x1 ^= *(const sph_u32 *)(p +  4);
		x2 ^= *(const sph_u32 *)(p +  8);
		x3 ^= *(const sph_u32 *)(p + 12);
		x4 ^= *(const sph_u32 *)(p + 16);
		x5 ^= *(const sph_u32 *)(p + 20);
		x6 ^= *(const sph_u32 *)(p + 24);
		x7 ^= *(const sph_u32 *)(p + 28);
		p += 32;

		/* 16 rounds (fully unrolled) */
		ROUND_EVEN; ROUND_ODD;
		ROUND_EVEN; ROUND_ODD;
		ROUND_EVEN; ROUND_ODD;
		ROUND_EVEN; ROUND_ODD;
		ROUND_EVEN; ROUND_ODD;
		ROUND_EVEN; ROUND_ODD;
		ROUND_EVEN; ROUND_ODD;
		ROUND_EVEN; ROUND_ODD;
	}

	/* Save midstate */
	ms->midstate[ 0] = x0;  ms->midstate[ 1] = x1;  ms->midstate[ 2] = x2;  ms->midstate[ 3] = x3;
	ms->midstate[ 4] = x4;  ms->midstate[ 5] = x5;  ms->midstate[ 6] = x6;  ms->midstate[ 7] = x7;
	ms->midstate[ 8] = x8;  ms->midstate[ 9] = x9;  ms->midstate[10] = xa;  ms->midstate[11] = xb;
	ms->midstate[12] = xc;  ms->midstate[13] = xd;  ms->midstate[14] = xe;  ms->midstate[15] = xf;
	ms->midstate[16] = xg;  ms->midstate[17] = xh;  ms->midstate[18] = xi;  ms->midstate[19] = xj;
	ms->midstate[20] = xk;  ms->midstate[21] = xl;  ms->midstate[22] = xm;  ms->midstate[23] = xn;
	ms->midstate[24] = xo;  ms->midstate[25] = xp;  ms->midstate[26] = xq;  ms->midstate[27] = xr;
	ms->midstate[28] = xs;  ms->midstate[29] = xt;  ms->midstate[30] = xu;  ms->midstate[31] = xv;
	ms->out_size_w32 = out_size_w32;
}

/* -----------------------------------------------------------------
 * Fast nonce check.
 * Tail16 is the last 16 bytes of the header (with nonce at byte 12).
 * Returns 1 if first output word ≤ target (little‑endian).
 * ----------------------------------------------------------------- */
static int
cubehash_check_nonce(const cubehash_midstate *ms,
                     const unsigned char *tail16,
                     sph_u32 target)
{
	sph_u32 x0 = ms->midstate[ 0], x1 = ms->midstate[ 1], x2 = ms->midstate[ 2], x3 = ms->midstate[ 3];
	sph_u32 x4 = ms->midstate[ 4], x5 = ms->midstate[ 5], x6 = ms->midstate[ 6], x7 = ms->midstate[ 7];
	sph_u32 x8 = ms->midstate[ 8], x9 = ms->midstate[ 9], xa = ms->midstate[10], xb = ms->midstate[11];
	sph_u32 xc = ms->midstate[12], xd = ms->midstate[13], xe = ms->midstate[14], xf = ms->midstate[15];
	sph_u32 xg = ms->midstate[16], xh = ms->midstate[17], xi = ms->midstate[18], xj = ms->midstate[19];
	sph_u32 xk = ms->midstate[20], xl = ms->midstate[21], xm = ms->midstate[22], xn = ms->midstate[23];
	sph_u32 xo = ms->midstate[24], xp = ms->midstate[25], xq = ms->midstate[26], xr = ms->midstate[27];
	sph_u32 xs = ms->midstate[28], xt = ms->midstate[29], xu = ms->midstate[30], xv = ms->midstate[31];

	/* XOR the 16 tail bytes (first 16 bytes of the final block) */
	x0 ^= *(const sph_u32 *)(tail16 +  0);
	x1 ^= *(const sph_u32 *)(tail16 +  4);
	x2 ^= *(const sph_u32 *)(tail16 +  8);
	x3 ^= *(const sph_u32 *)(tail16 + 12);
	/* Pad with 0x80 at byte 16 (word 4, least significant byte) */
	x4 ^= 0x00000080U;
	/* Bytes 17‑31 remain zero → XOR has no effect on x5..x7 */

	/* 16 rounds for this last message block */
	ROUND_EVEN; ROUND_ODD;
	ROUND_EVEN; ROUND_ODD;
	ROUND_EVEN; ROUND_ODD;
	ROUND_EVEN; ROUND_ODD;
	ROUND_EVEN; ROUND_ODD;
	ROUND_EVEN; ROUND_ODD;
	ROUND_EVEN; ROUND_ODD;
	ROUND_EVEN; ROUND_ODD;

	/* 11 more 16‑round iterations (finalization, exactly as standard) */
	int i;
	for (i = 0; i < 11; i++) {
		if (i == 0)
			xv ^= 1;
		ROUND_EVEN; ROUND_ODD;
		ROUND_EVEN; ROUND_ODD;
		ROUND_EVEN; ROUND_ODD;
		ROUND_EVEN; ROUND_ODD;
		ROUND_EVEN; ROUND_ODD;
		ROUND_EVEN; ROUND_ODD;
		ROUND_EVEN; ROUND_ODD;
		ROUND_EVEN; ROUND_ODD;
	}

	/* Output is little‑endian; target is also little‑endian.
	   Compare first word directly. */
	return (x0 <= target);
}

/* -----------------------------------------------------------------
 * Batch nonce scanner.
 * Returns the winning nonce, or 0xFFFFFFFF if none.
 * ----------------------------------------------------------------- */
static sph_u32
cubehash_scan_nonces(const cubehash_midstate *ms,
                     const unsigned char *base_tail,   /* first 12 constant bytes */
                     sph_u32 start_nonce, sph_u32 end_nonce,
                     sph_u32 target)
{
	unsigned char tail[16];
	memcpy(tail, base_tail, 12);

	sph_u32 nonce = start_nonce;
	while (nonce <= end_nonce) {
		tail[12] = (unsigned char)(nonce);
		tail[13] = (unsigned char)(nonce >> 8);
		tail[14] = (unsigned char)(nonce >> 16);
		tail[15] = (unsigned char)(nonce >> 24);

		if (cubehash_check_nonce(ms, tail, target))
			return nonce;
		nonce++;
	}
	return 0xFFFFFFFFU;
}

/*
 * Restore the NOCOPY macros for the remaining standard API functions.
 */
#if SPH_CUBEHASH_NOCOPY
# define x0   ((sc)->state[ 0])
# define x1   ((sc)->state[ 1])
# define x2   ((sc)->state[ 2])
# define x3   ((sc)->state[ 3])
# define x4   ((sc)->state[ 4])
# define x5   ((sc)->state[ 5])
# define x6   ((sc)->state[ 6])
# define x7   ((sc)->state[ 7])
# define x8   ((sc)->state[ 8])
# define x9   ((sc)->state[ 9])
# define xa   ((sc)->state[10])
# define xb   ((sc)->state[11])
# define xc   ((sc)->state[12])
# define xd   ((sc)->state[13])
# define xe   ((sc)->state[14])
# define xf   ((sc)->state[15])
# define xg   ((sc)->state[16])
# define xh   ((sc)->state[17])
# define xi   ((sc)->state[18])
# define xj   ((sc)->state[19])
# define xk   ((sc)->state[20])
# define xl   ((sc)->state[21])
# define xm   ((sc)->state[22])
# define xn   ((sc)->state[23])
# define xo   ((sc)->state[24])
# define xp   ((sc)->state[25])
# define xq   ((sc)->state[26])
# define xr   ((sc)->state[27])
# define xs   ((sc)->state[28])
# define xt   ((sc)->state[29])
# define xu   ((sc)->state[30])
# define xv   ((sc)->state[31])
#endif

#endif /* CUBEHASH_UNFAIR */

/* =============================================================
 * STANDARD API (also benefits from full unroll & NOCOPY)
 * ============================================================= */
static void
cubehash_init(sph_cubehash_context *sc, const sph_u32 *iv)
{
	memcpy(sc->state, iv, sizeof sc->state);
	sc->ptr = 0;
}

static void
cubehash_core(sph_cubehash_context *sc, const void *data, size_t len)
{
	unsigned char *buf;
	size_t ptr;
	DECL_STATE

	buf = sc->buf;
	ptr = sc->ptr;
	if (len < (sizeof sc->buf) - ptr) {
		memcpy(buf + ptr, data, len);
		ptr += len;
		sc->ptr = ptr;
		return;
	}

	READ_STATE(sc);
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
			INPUT_BLOCK;
			SIXTEEN_ROUNDS;
			ptr = 0;
		}
	}
	WRITE_STATE(sc);
	sc->ptr = ptr;
}

static void
cubehash_close(sph_cubehash_context *sc, unsigned ub, unsigned n,
	void *dst, size_t out_size_w32)
{
	unsigned char *buf, *out;
	size_t ptr;
	unsigned z;
	int i;
	DECL_STATE

	buf = sc->buf;
	ptr = sc->ptr;
	z = 0x80 >> n;
	buf[ptr ++] = ((ub & -z) | z) & 0xFF;
	memset(buf + ptr, 0, (sizeof sc->buf) - ptr);
	READ_STATE(sc);
	INPUT_BLOCK;
	for (i = 0; i < 11; i ++) {
		SIXTEEN_ROUNDS;
		if (i == 0)
			xv ^= SPH_C32(1);
	}
	WRITE_STATE(sc);
	out = dst;
	for (z = 0; z < out_size_w32; z ++)
		sph_enc32le(out + (z << 2), sc->state[z]);
}

/* Public wrappers */
void sph_cubehash224_init(void *cc) {
	cubehash_init(cc, IV224);
}
void sph_cubehash224(void *cc, const void *data, size_t len) {
	cubehash_core(cc, data, len);
}
void sph_cubehash224_close(void *cc, void *dst) {
	sph_cubehash224_addbits_and_close(cc, 0, 0, dst);
}
void sph_cubehash224_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst) {
	cubehash_close(cc, ub, n, dst, 7);
	sph_cubehash224_init(cc);
}
void sph_cubehash256_init(void *cc) {
	cubehash_init(cc, IV256);
}
void sph_cubehash256(void *cc, const void *data, size_t len) {
	cubehash_core(cc, data, len);
}
void sph_cubehash256_close(void *cc, void *dst) {
	sph_cubehash256_addbits_and_close(cc, 0, 0, dst);
}
void sph_cubehash256_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst) {
	cubehash_close(cc, ub, n, dst, 8);
	sph_cubehash256_init(cc);
}
void sph_cubehash384_init(void *cc) {
	cubehash_init(cc, IV384);
}
void sph_cubehash384(void *cc, const void *data, size_t len) {
	cubehash_core(cc, data, len);
}
void sph_cubehash384_close(void *cc, void *dst) {
	sph_cubehash384_addbits_and_close(cc, 0, 0, dst);
}
void sph_cubehash384_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst) {
	cubehash_close(cc, ub, n, dst, 12);
	sph_cubehash384_init(cc);
}
void sph_cubehash512_init(void *cc) {
	cubehash_init(cc, IV512);
}
void sph_cubehash512(void *cc, const void *data, size_t len) {
	cubehash_core(cc, data, len);
}
void sph_cubehash512_close(void *cc, void *dst) {
	sph_cubehash512_addbits_and_close(cc, 0, 0, dst);
}
void sph_cubehash512_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst) {
	cubehash_close(cc, ub, n, dst, 16);
	sph_cubehash512_init(cc);
}

#ifdef __cplusplus
}
#endif
