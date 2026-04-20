#include <miner.h>

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

#include <sha3/sph_blake.h>
#include <sha3/sph_bmw.h>
#include <sha3/sph_groestl.h>
#include <sha3/sph_jh.h>
#include <sha3/sph_keccak.h>
#include <sha3/sph_skein.h>
#include <sha3/sph_luffa.h>
#include <sha3/sph_cubehash.h>
#include <sha3/sph_shavite.h>
#include <sha3/sph_simd.h>
#include <sha3/sph_echo.h>
#include <sha3/sph_hamsi.h>
#include <sha3/sph_fugue.h>
#include <sha3/sph_shabal.h>
#include <sha3/sph_whirlpool.h>
#include <sha3/sph_sha2.h>
#include <yespower-1.0.1/yespower.h>

/* ── ARM / Android compiler hints ─────────────────────────────────────── */
#if defined(__ARM_ARCH) || defined(__aarch64__)
  #define LIKELY(x)        __builtin_expect(!!(x), 1)
  #define UNLIKELY(x)      __builtin_expect(!!(x), 0)
  #define PREFETCH_R(p)    __builtin_prefetch((p), 0, 1)
  #define PREFETCH_W(p)    __builtin_prefetch((p), 1, 1)
  #define HOT              __attribute__((hot, optimize("O3")))
  #define FLATTEN          __attribute__((flatten))
  #define NOINLINE         __attribute__((noinline))
  #define CACHE_LINE       64
  #define ALIGN64          __attribute__((aligned(64)))
  #define ALIGN128         __attribute__((aligned(128)))
  #if defined(__aarch64__)
    #include <arm_neon.h>
    #define HAS_NEON 1
  #elif defined(__ARM_NEON)
    #include <arm_neon.h>
    #define HAS_NEON 1
  #endif
#else
  #define LIKELY(x)        (x)
  #define UNLIKELY(x)      (x)
  #define PREFETCH_R(p)
  #define PREFETCH_W(p)
  #define HOT
  #define FLATTEN
  #define NOINLINE
  #define CACHE_LINE       64
  #define ALIGN64          __attribute__((aligned(64)))
  #define ALIGN128         __attribute__((aligned(128)))
#endif

/* ── Constants ─────────────────────────────────────────────────────────── */
#define MINOTAUR_ALGO_COUNT  16
#define NODE_COUNT           22
#define TREE_DEPTH           7
#define NONCE_BATCH          16
#define BIAS_BUCKETS         256
#define BIAS_EPOCH_NONCES    65536
#define BIAS_WINDOW          16
#define PRINT_INTERVAL       262144

#define FAST_ALGO_MASK       0xFFFFu   /* all 16 enabled; tune per coin */

/* ── yespower params ───────────────────────────────────────────────────── */
static const yespower_params_t yespower_params = {
    YESPOWER_1_0, 2048, 8, "et in arcadia ego", 17
};

static const uint16_t algo_cost[17] = {
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1000
};

#ifndef COST_THRESHOLD
#define COST_THRESHOLD 50
#endif

/* ── Static child index table ─────────────────────────────────────────── */
static const int8_t node_children[NODE_COUNT][2] = {
    { 1, 2},{ 3, 4},{ 5, 6},{ 7, 8},{ 9,10},{11,12},{13,14},
    {15,16},{15,16},{15,16},{15,16},
    {17,18},{17,18},{17,18},{17,18},
    {19,20},{19,20},{19,20},{19,20},
    {21,21},{21,21},
    {-1,-1}
};

static uint8_t path_bias_prefer[MINOTAUR_ALGO_COUNT] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};

static uint32_t path_left_count[MINOTAUR_ALGO_COUNT]  = {0};
static uint32_t path_right_count[MINOTAUR_ALGO_COUNT] = {0};
static uint32_t path_left_wins[MINOTAUR_ALGO_COUNT]   = {0};
static uint32_t path_right_wins[MINOTAUR_ALGO_COUNT]  = {0};

typedef struct {
    uint64_t  attempts;
    uint64_t  valid_hashes;
    uint64_t  shares_found;
    uint64_t  yespower_skipped;
    uint64_t  early_rejected;
    uint64_t  algo_hits[MINOTAUR_ALGO_COUNT];
    uint64_t  algo_share_hits[MINOTAUR_ALGO_COUNT];
    uint32_t  bucket_hits[BIAS_BUCKETS];
    uint32_t  bucket_score[BIAS_BUCKETS];
    uint32_t  nonce_mod_hits[256];
    uint32_t  nonce_mod_score[256];
    double    hashrate_avg;
    pthread_mutex_t lock;
} bias_stats_t ALIGN64;

static bias_stats_t g_bias ALIGN64;
static int          g_bias_init = 0;

static void bias_init(void)
{
    if (g_bias_init) return;
    memset(&g_bias, 0, sizeof(g_bias));
    for (int i = 0; i < BIAS_BUCKETS; i++) g_bias.bucket_score[i]   = 1;
    for (int i = 0; i < 256; i++)          g_bias.nonce_mod_score[i] = 1;
    pthread_mutex_init(&g_bias.lock, NULL);
    g_bias_init = 1;
}

static HOT inline uint8_t
bias_bucket_key(const unsigned char *h)
{
    return (uint8_t)(
        ((h[0] & 0xC0) >> 0) | ((h[1] & 0xC0) >> 2) |
        ((h[2] & 0xC0) >> 4) | ((h[3] & 0xC0) >> 6)
    );
}

static NOINLINE void
bias_record_share(uint8_t bucket, uint8_t nonce_mod,
                  const unsigned int *algos, int root_dir)
{
    pthread_mutex_lock(&g_bias.lock);
    g_bias.shares_found++;
    g_bias.bucket_hits[bucket]++;
    g_bias.nonce_mod_hits[nonce_mod]++;
    g_bias.bucket_score[bucket] =
        (g_bias.bucket_score[bucket] * 7 + g_bias.bucket_hits[bucket] * 256) / 8;
    g_bias.nonce_mod_score[nonce_mod] =
        (g_bias.nonce_mod_score[nonce_mod] * 7 +
         g_bias.nonce_mod_hits[nonce_mod] * 256) / 8;
    for (int i = 0; i < NODE_COUNT; i++) {
        unsigned int a = algos[i];
        if (a < MINOTAUR_ALGO_COUNT) {
            g_bias.algo_hits[a]++;
            if (i == 0) g_bias.algo_share_hits[a]++;
        }
    }
    unsigned int ra = algos[0];
    if (ra < MINOTAUR_ALGO_COUNT) {
        if (root_dir == 0) path_left_wins[ra]++;
        else               path_right_wins[ra]++;
        if (path_left_wins[ra] > path_right_wins[ra] * 2)
            path_bias_prefer[ra] = 0;
        else if (path_right_wins[ra] > path_left_wins[ra] * 2)
            path_bias_prefer[ra] = 1;
        else
            path_bias_prefer[ra] = 0xFF;
    }
    pthread_mutex_unlock(&g_bias.lock);
}

static NOINLINE void bias_decay(void)
{
    pthread_mutex_lock(&g_bias.lock);
    for (int i = 0; i < BIAS_BUCKETS; i++) {
        g_bias.bucket_score[i] = (g_bias.bucket_score[i] * 252) / 256 + 1;
        g_bias.bucket_hits[i]  = (g_bias.bucket_hits[i]  * 252) / 256;
    }
    for (int i = 0; i < 256; i++) {
        g_bias.nonce_mod_score[i] = (g_bias.nonce_mod_score[i] * 252) / 256 + 1;
        g_bias.nonce_mod_hits[i]  = (g_bias.nonce_mod_hits[i]  * 252) / 256;
    }
    for (int i = 0; i < MINOTAUR_ALGO_COUNT; i++) {
        path_left_wins[i]   = (path_left_wins[i]   * 3) / 4;
        path_right_wins[i]  = (path_right_wins[i]  * 3) / 4;
        path_left_count[i]  = (path_left_count[i]  * 3) / 4;
        path_right_count[i] = (path_right_count[i] * 3) / 4;
    }
    pthread_mutex_unlock(&g_bias.lock);
}

static NOINLINE void bias_print_stats(void)
{
    pthread_mutex_lock(&g_bias.lock);
    fprintf(stderr,
        "[BIAS] attempts=%" PRIu64 " valid=%" PRIu64
        " shares=%" PRIu64 " yp_skip=%" PRIu64
        " early_rej=%" PRIu64 "\n",
        g_bias.attempts, g_bias.valid_hashes,
        g_bias.shares_found, g_bias.yespower_skipped,
        g_bias.early_rejected);
    fprintf(stderr, "[BIAS] algo_share_hits:");
    for (int i = 0; i < MINOTAUR_ALGO_COUNT; i++)
        fprintf(stderr, " %"PRIu64, g_bias.algo_share_hits[i]);
    fprintf(stderr, "\n");
    fprintf(stderr, "[BIAS] path_pref:");
    for (int i = 0; i < MINOTAUR_ALGO_COUNT; i++)
        fprintf(stderr, " %d", (int)path_bias_prefer[i]);
    fprintf(stderr, "\n");
    pthread_mutex_unlock(&g_bias.lock);
}

typedef struct { uint32_t nonce; uint32_t score; } nonce_candidate_t;

static HOT inline void
bias_reorder_window(uint32_t base, uint32_t max_nonce,
                    nonce_candidate_t *out, int *cnt)
{
    int count = 0;
    for (uint32_t n = base;
         n < base + BIAS_WINDOW && n < max_nonce; n++) {
        uint32_t score = g_bias.nonce_mod_score[n & 0xFF];
        int pos = count;
        while (pos > 0 && out[pos-1].score < score) {
            if (pos < BIAS_WINDOW) out[pos] = out[pos-1];
            pos--;
        }
        if (pos < BIAS_WINDOW) { out[pos].nonce = n; out[pos].score = score; }
        if (count < BIAS_WINDOW) count++;
    }
    *cnt = count;
}

typedef struct {
    sph_blake512_context    blake;
    sph_bmw512_context      bmw;
    sph_cubehash512_context cubehash;
    sph_echo512_context     echo;
    sph_fugue512_context    fugue;
    sph_groestl512_context  groestl;
    sph_hamsi512_context    hamsi;
    sph_jh512_context       jh;
    sph_keccak512_context   keccak;
    sph_luffa512_context    luffa;
    sph_shabal512_context   shabal;
    sph_shavite512_context  shavite;
    sph_simd512_context     simd;
    sph_skein512_context    skein;
    sph_whirlpool_context   whirlpool;
    sph_sha512_context      sha2;
} preinit_contexts_t;

static preinit_contexts_t preinit_ctx ALIGN64;
static int preinit_done = 0;

static NOINLINE void init_precomputed_contexts(void)
{
    if (LIKELY(preinit_done)) return;
    sph_blake512_init   (&preinit_ctx.blake);
    sph_bmw512_init     (&preinit_ctx.bmw);
    sph_cubehash512_init(&preinit_ctx.cubehash);
    sph_echo512_init    (&preinit_ctx.echo);
    sph_fugue512_init   (&preinit_ctx.fugue);
    sph_groestl512_init (&preinit_ctx.groestl);
    sph_hamsi512_init   (&preinit_ctx.hamsi);
    sph_sha512_init     (&preinit_ctx.sha2);
    sph_jh512_init      (&preinit_ctx.jh);
    sph_keccak512_init  (&preinit_ctx.keccak);
    sph_luffa512_init   (&preinit_ctx.luffa);
    sph_shabal512_init  (&preinit_ctx.shabal);
    sph_shavite512_init (&preinit_ctx.shavite);
    sph_simd512_init    (&preinit_ctx.simd);
    sph_skein512_init   (&preinit_ctx.skein);
    sph_whirlpool_init  (&preinit_ctx.whirlpool);
    preinit_done = 1;
}

typedef struct TortureNode {
    unsigned int        algo;
    struct TortureNode *childLeft;
    struct TortureNode *childRight;
} TortureNode;

typedef struct {
    union {
        sph_blake512_context    blake;
        sph_bmw512_context      bmw;
        sph_cubehash512_context cubehash;
        sph_echo512_context     echo;
        sph_fugue512_context    fugue;
        sph_groestl512_context  groestl;
        sph_hamsi512_context    hamsi;
        sph_jh512_context       jh;
        sph_keccak512_context   keccak;
        sph_luffa512_context    luffa;
        sph_shabal512_context   shabal;
        sph_shavite512_context  shavite;
        sph_simd512_context     simd;
        sph_skein512_context    skein;
        sph_whirlpool_context   whirlpool;
        sph_sha512_context      sha2;
    } ctx;
    sph_sha512_context ctx_sha2_nonce;
    TortureNode        nodes[NODE_COUNT];
    unsigned int       node_algos_cache[NODE_COUNT];
} TortureGarden;

typedef struct {
    unsigned int root_algo;
    uint8_t      dir_bit;
    unsigned char step1_hash[64] ALIGN64;
    TortureNode  *step1_node;
    uint32_t     last_nonce;
    int          valid;
} reuse_cache_t;

static __thread reuse_cache_t t_reuse = {0};

static HOT inline void copy64(void * __restrict__ d, const void * __restrict__ s)
{
#if defined(HAS_NEON) && defined(__aarch64__)
    vst1q_u8((uint8_t*)d,      vld1q_u8((const uint8_t*)s));
    vst1q_u8((uint8_t*)d + 16, vld1q_u8((const uint8_t*)s + 16));
    vst1q_u8((uint8_t*)d + 32, vld1q_u8((const uint8_t*)s + 32));
    vst1q_u8((uint8_t*)d + 48, vld1q_u8((const uint8_t*)s + 48));
#else
    memcpy(d, s, 64);
#endif
}

static HOT inline void copy32(void * __restrict__ d, const void * __restrict__ s)
{
#if defined(HAS_NEON) && defined(__aarch64__)
    vst1q_u8((uint8_t*)d,      vld1q_u8((const uint8_t*)s));
    vst1q_u8((uint8_t*)d + 16, vld1q_u8((const uint8_t*)s + 16));
#else
    memcpy(d, s, 32);
#endif
}

static HOT inline int
neon_hash_le_target(const uint32_t * __restrict__ hash,
                    const uint32_t * __restrict__ target)
{
    for (int i = 7; i >= 0; i--) {
        if (hash[i] < target[i]) return 1;
        if (hash[i] > target[i]) return 0;
    }
    return 1;
}

static inline void init_garden(TortureGarden * __restrict__ g)
{
    TortureNode *n = g->nodes;
    for (int i = 0; i < NODE_COUNT; i++) {
        int l = node_children[i][0], r = node_children[i][1];
        n[i].childLeft  = (l >= 0) ? &n[l] : NULL;
        n[i].childRight = (r >= 0) ? &n[r] : NULL;
    }
}

static HOT inline void
algo_blake_fast(unsigned char * __restrict__ out,
                const unsigned char * __restrict__ in)
{
    sph_blake512_context ctx;
    ctx = preinit_ctx.blake;
    sph_blake512      (&ctx, in, 64);
    sph_blake512_close(&ctx, out);
}

static HOT inline void
algo_skein_fast(unsigned char * __restrict__ out,
                const unsigned char * __restrict__ in)
{
    sph_skein512_context ctx;
    ctx = preinit_ctx.skein;
    sph_skein512      (&ctx, in, 64);
    sph_skein512_close(&ctx, out);
}

static HOT inline void
algo_bmw_fast(unsigned char * __restrict__ out,
              const unsigned char * __restrict__ in)
{
    sph_bmw512_context ctx;
    ctx = preinit_ctx.bmw;
    sph_bmw512      (&ctx, in, 64);
    sph_bmw512_close(&ctx, out);
}

static HOT inline void
algo_keccak_fast(unsigned char * __restrict__ out,
                 const unsigned char * __restrict__ in)
{
    sph_keccak512_context ctx;
    ctx = preinit_ctx.keccak;
    sph_keccak512      (&ctx, in, 64);
    sph_keccak512_close(&ctx, out);
}

static HOT inline void
get_hash(unsigned char * __restrict__ output,
         const unsigned char * __restrict__ input,
         TortureGarden * __restrict__ garden,
         unsigned int algo)
{
    unsigned char ALIGN64 hash[64];

    switch (algo) {
    case 0:  algo_blake_fast (hash, input); break;
    case 1:  algo_bmw_fast   (hash, input); break;
    case 14: algo_skein_fast (hash, input); break;
    case 9:  algo_keccak_fast(hash, input); break;
    case 2:
        garden->ctx.cubehash = preinit_ctx.cubehash;
        sph_cubehash512      (&garden->ctx.cubehash, input, 64);
        sph_cubehash512_close(&garden->ctx.cubehash, hash);
        break;
    case 3:
        garden->ctx.echo = preinit_ctx.echo;
        sph_echo512      (&garden->ctx.echo, input, 64);
        sph_echo512_close(&garden->ctx.echo, hash);
        break;
    case 4:
        garden->ctx.fugue = preinit_ctx.fugue;
        sph_fugue512      (&garden->ctx.fugue, input, 64);
        sph_fugue512_close(&garden->ctx.fugue, hash);
        break;
    case 5:
        garden->ctx.groestl = preinit_ctx.groestl;
        sph_groestl512      (&garden->ctx.groestl, input, 64);
        sph_groestl512_close(&garden->ctx.groestl, hash);
        break;
    case 6:
        garden->ctx.hamsi = preinit_ctx.hamsi;
        sph_hamsi512      (&garden->ctx.hamsi, input, 64);
        sph_hamsi512_close(&garden->ctx.hamsi, hash);
        break;
    case 7:
        garden->ctx.sha2 = preinit_ctx.sha2;
        sph_sha512      (&garden->ctx.sha2, input, 64);
        sph_sha512_close(&garden->ctx.sha2, hash);
        break;
    case 8:
        garden->ctx.jh = preinit_ctx.jh;
        sph_jh512      (&garden->ctx.jh, input, 64);
        sph_jh512_close(&garden->ctx.jh, hash);
        break;
    case 10:
        garden->ctx.luffa = preinit_ctx.luffa;
        sph_luffa512      (&garden->ctx.luffa, input, 64);
        sph_luffa512_close(&garden->ctx.luffa, hash);
        break;
    case 11:
        garden->ctx.shabal = preinit_ctx.shabal;
        sph_shabal512      (&garden->ctx.shabal, input, 64);
        sph_shabal512_close(&garden->ctx.shabal, hash);
        break;
    case 12:
        garden->ctx.shavite = preinit_ctx.shavite;
        sph_shavite512      (&garden->ctx.shavite, input, 64);
        sph_shavite512_close(&garden->ctx.shavite, hash);
        break;
    case 13:
        garden->ctx.simd = preinit_ctx.simd;
        sph_simd512      (&garden->ctx.simd, input, 64);
        sph_simd512_close(&garden->ctx.simd, hash);
        break;
    case 15:
        garden->ctx.whirlpool = preinit_ctx.whirlpool;
        sph_whirlpool      (&garden->ctx.whirlpool, input, 64);
        sph_whirlpool_close(&garden->ctx.whirlpool, hash);
        break;
    case 16:
        memset(hash + 32, 0, 32);
        yespower_tls(input, 64, &yespower_params, (yespower_binary_t*)hash);
        break;
    default:
        memset(hash, 0, 64);
    }

    copy64(output, hash);
}

#define GARDEN_STEP_BIASED()                                             \
    do {                                                                 \
        unsigned int _algo = node->algo;                                 \
        uint8_t _pref = (_algo < MINOTAUR_ALGO_COUNT)                   \
                        ? path_bias_prefer[_algo] : 0;                  \
        if (_pref == 0) {                                                \
            PREFETCH_R(node->childLeft);                                 \
            PREFETCH_R(node->childRight);                                \
        } else {                                                         \
            PREFETCH_R(node->childRight);                                \
            PREFETCH_R(node->childLeft);                                 \
        }                                                                \
        get_hash(partial, hash, garden, _algo);                          \
        int _left = (_algo == MINOTAUR_ALGO_COUNT)                       \
                    ? 1 : ((partial[63] & 1) == 0);                      \
        if (_algo < MINOTAUR_ALGO_COUNT) {                               \
            if (_left) __atomic_fetch_add(&path_left_count[_algo],  1,  \
                                          __ATOMIC_RELAXED);             \
            else       __atomic_fetch_add(&path_right_count[_algo], 1,  \
                                          __ATOMIC_RELAXED);             \
        }                                                                \
        TortureNode *_next = _left ? node->childLeft : node->childRight; \
        if (UNLIKELY(!_next)) goto traverse_done;                        \
        copy64(hash, partial);                                           \
        node = _next;                                                    \
    } while (0)

static HOT FLATTEN void
traverse_garden_fast(TortureGarden * __restrict__ garden,
                     void * __restrict__ hash,
                     TortureNode *start_node)
{
    unsigned char ALIGN64 partial[64];
    TortureNode *node = start_node;

    GARDEN_STEP_BIASED();
    GARDEN_STEP_BIASED();
    GARDEN_STEP_BIASED();
    GARDEN_STEP_BIASED();
    GARDEN_STEP_BIASED();
    GARDEN_STEP_BIASED();
    GARDEN_STEP_BIASED();

traverse_done:;
}

static HOT FLATTEN void
traverse_garden_reuse(TortureGarden * __restrict__ garden,
                      void * __restrict__ hash,
                      TortureNode *start_node)
{
    unsigned char ALIGN64 partial[64];
    TortureNode *node = start_node;

    GARDEN_STEP_BIASED();
    GARDEN_STEP_BIASED();
    GARDEN_STEP_BIASED();
    GARDEN_STEP_BIASED();
    GARDEN_STEP_BIASED();
    GARDEN_STEP_BIASED();

traverse_done:;
}
#undef GARDEN_STEP_BIASED

static HOT inline void fast_be32enc(uint32_t *dst, uint32_t v)
{
#if defined(__aarch64__) || defined(__ARM_ARCH)
    *dst = __builtin_bswap32(v);
#else
    *dst = ((v & 0xFF) << 24) | ((v & 0xFF00) << 8) |
           ((v >> 8) & 0xFF00) | ((v >> 24) & 0xFF);
#endif
}

static HOT inline int
share_fast_path(const uint32_t * __restrict__ hash,
                const uint32_t * __restrict__ ptarget,
                uint32_t Htarg)
{
    if (LIKELY(hash[7] > Htarg)) return 0;
    if (!neon_hash_le_target(hash, ptarget)) return 0;
    return fulltest(hash, ptarget);
}

static HOT uint8_t
minotaurhash_unfair(void * __restrict__ output,
                    const void * __restrict__ input,
                    bool minotaurX,
                    const sph_sha512_context * __restrict__ precomputed_sha,
                    unsigned int * __restrict__ algos_out,
                    int * __restrict__ root_dir_out)
{
    TortureGarden garden ALIGN64;
    init_garden(&garden);

    garden.ctx_sha2_nonce = *precomputed_sha;
    sph_sha512      (&garden.ctx_sha2_nonce, (const uint8_t*)input + 76, 4);
    unsigned char ALIGN64 hash[64];
    sph_sha512_close(&garden.ctx_sha2_nonce, hash);

    uint8_t bucket = bias_bucket_key(hash);

    unsigned int root_algo = 0;
    {
        TortureNode *n = garden.nodes;
        for (int i = 0; i < NODE_COUNT; i++) {
            unsigned int a = (unsigned int)(hash[i] % MINOTAUR_ALGO_COUNT);
            n[i].algo = a;
            if (algos_out) algos_out[i] = a;
        }
        root_algo = garden.nodes[0].algo;
    }

    if (minotaurX) {
        garden.nodes[NODE_COUNT - 1].algo = MINOTAUR_ALGO_COUNT;
        if (algos_out) algos_out[NODE_COUNT - 1] = MINOTAUR_ALGO_COUNT;
    }

    if (!(FAST_ALGO_MASK & (1u << root_algo))) {
        __atomic_fetch_add(&g_bias.early_rejected, 1, __ATOMIC_RELAXED);
        memset(output, 0xFF, 32);
        return bucket;
    }

    {
        int limit = minotaurX ? (NODE_COUNT - 1) : NODE_COUNT;
        for (int i = 0; i < limit; i++) {
            if (UNLIKELY(garden.nodes[i].algo == MINOTAUR_ALGO_COUNT)) {
                __atomic_fetch_add(&g_bias.yespower_skipped, 1, __ATOMIC_RELAXED);
                memset(output, 0xFF, 32);
                return bucket;
            }
        }
        __atomic_fetch_add(&g_bias.valid_hashes, 1, __ATOMIC_RELAXED);
    }

#ifdef ENABLE_HASH_PREFILTER
    if ((hash[7] & 0x03) == 0x03) {
        __atomic_fetch_add(&g_bias.early_rejected, 1, __ATOMIC_RELAXED);
        memset(output, 0xFF, 32);
        return bucket;
    }
#endif

    int reused = 0;
    TortureNode *traverse_start = &garden.nodes[0];

    if (t_reuse.valid && t_reuse.root_algo == root_algo) {
        uint8_t this_dir_bit = (uint8_t)(hash[63] & 1);
        if (t_reuse.dir_bit == this_dir_bit) {
            copy64(hash, t_reuse.step1_hash);
            traverse_start = t_reuse.step1_node;
            reused = 1;
        }
    }

    if (!reused) {
        traverse_garden_fast(&garden, hash, &garden.nodes[0]);

        t_reuse.root_algo  = root_algo;
        t_reuse.dir_bit    = (uint8_t)(((unsigned char*)hash)[63] & 1);
        copy64(t_reuse.step1_hash, hash);
        t_reuse.step1_node = (t_reuse.dir_bit == 0)
                             ? garden.nodes[0].childLeft
                             : garden.nodes[0].childRight;
        t_reuse.valid      = 1;
    } else {
        traverse_garden_reuse(&garden, hash, traverse_start);
    }

    if (root_dir_out)
        *root_dir_out = (t_reuse.valid && !reused) ? (int)t_reuse.dir_bit : 0;

    copy32(output, hash);
    return bucket;
}

/* ── scanhash_minotaur ─────────────────────────────────────────────────── */
int scanhash_minotaur(int thr_id, struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, bool minotaurX)
{
    uint32_t ALIGN64 hash[8];
    uint32_t ALIGN64 endiandata[20];
    uint32_t *pdata   = work->data;
    uint32_t *ptarget = work->target;

    const uint32_t Htarg       = ptarget[7];
    const uint32_t first_nonce = pdata[19];
    uint32_t       nonce       = first_nonce;
    volatile uint8_t *restart  = &(work_restart[thr_id].restart);

    if (opt_benchmark)
        ptarget[7] = 0x0cff;

    init_precomputed_contexts();
    bias_init();

    for (int k = 0; k < 19; k++)
        be32enc(&endiandata[k], pdata[k]);

    sph_sha512_context sha_pre;
    sph_sha512_init(&sha_pre);
    sph_sha512(&sha_pre, endiandata, 76);

    unsigned int node_algos[NODE_COUNT];
    int          root_dir;
    uint32_t     epoch_counter = 0;
    uint32_t     print_counter = 0;

    t_reuse.valid = 0;

    nonce_candidate_t candidates[BIAS_WINDOW];

    while (LIKELY(nonce < max_nonce) && LIKELY(!(*restart))) {

        int cand_count = 0;
        bias_reorder_window(nonce, max_nonce, candidates, &cand_count);

        for (int ci = 0; ci < cand_count; ci++) {
            uint32_t n = candidates[ci].nonce;

            fast_be32enc(&endiandata[19], n);

            uint8_t bucket = minotaurhash_unfair(
                hash, endiandata, minotaurX, &sha_pre,
                node_algos, &root_dir);

            __atomic_fetch_add(&g_bias.attempts, 1, __ATOMIC_RELAXED);
            epoch_counter++;
            print_counter++;

            if (!share_fast_path(hash, ptarget, Htarg))
                continue;

            if (fulltest(hash, ptarget)) {
                work_set_target_ratio(work, hash);
                pdata[19] = n;
                *hashes_done = n - first_nonce;
                bias_record_share(bucket, (uint8_t)(n & 0xFF),
                                  node_algos, root_dir);
                return 1;
            }
        }

        nonce += cand_count;

        if (UNLIKELY(epoch_counter >= BIAS_EPOCH_NONCES)) {
            bias_decay();
            epoch_counter = 0;
        }
        if (UNLIKELY(print_counter >= PRINT_INTERVAL)) {
            bias_print_stats();
            print_counter = 0;
        }
    }

    pdata[19] = nonce;
    *hashes_done = nonce - first_nonce + 1;
    return 0;
}

/* ────────────────────────────────────────────────────────────────────────
 * Wrapper required by miner.h (called from print_hash_tests)
 * ──────────────────────────────────────────────────────────────────────── */
void minotaurhash(void *output, const void *input, bool minotaurX)
{
    init_precomputed_contexts();
    bias_init();

    sph_sha512_context sha_pre;
    sph_sha512_init(&sha_pre);
    sph_sha512(&sha_pre, input, 76);

    unsigned int dummy_algos[NODE_COUNT];
    int dummy_dir;

    minotaurhash_unfair(output, input, minotaurX, &sha_pre,
                        dummy_algos, &dummy_dir);
}
