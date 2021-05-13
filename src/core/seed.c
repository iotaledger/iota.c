// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "core/seed.h"
#include "crypto/iota_crypto.h"

void random_seed(byte_t seed[]) { iota_crypto_randombytes(seed, IOTA_SEED_BYTES); }

void random_seed_hex(byte_t seed[]) { iota_crypto_randombytes(seed, IOTA_SEED_HEX_BYTES); }
