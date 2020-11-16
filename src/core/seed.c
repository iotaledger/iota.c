#include "core/seed.h"

void random_seed(byte_t seed[]) { iota_crypto_randombytes(seed, IOTA_SEED_BYTES); }
