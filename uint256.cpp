#include "uint256.h"

#ifdef __cplusplus
extern "C"{
#endif

#include "miner.h"

// compute the diff ratio between a found hash and the target
// (added const to hash parameter for consistency)
double hash_target_ratio(const uint32_t* hash, uint32_t* target)
{
	uint256 h, t;
	double dhash;

	if (!opt_showdiff)
		return 0.0;

	memcpy(&t, (void*) target, 32);
	memcpy(&h, (void*) hash, 32);

	dhash = h.getdouble();
	if (dhash > 0.)
		return t.getdouble() / dhash;
	else
		return dhash;
}

// store the share ratio in work struct
// FIXED: added const to hash parameter to match miner.h
void work_set_target_ratio(struct work* work, const uint32_t* hash)
{
	// only if the option is enabled (to reduce cpu usage)
	if (opt_showdiff && work) {
		// Cast away const inside – safe because hash_target_ratio only reads
		work->shareratio = hash_target_ratio(hash, work->target);
		work->sharediff = work->targetdiff * work->shareratio;
		if (opt_debug)
			applog(LOG_DEBUG, "share diff %.5f (%.1fx)", work->sharediff, work->shareratio);
	}
}

#ifdef __cplusplus
}
#endif
