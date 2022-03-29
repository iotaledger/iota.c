// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>
#include <unity/unity.h>

#include "core/utils/byte_buffer.h"
#include "core/utils/slip10.h"
#include "crypto/iota_crypto.h"
#include "slip10_vector.h"

void setUp(void) {}

void tearDown(void) {}

void test_bip32path() {
  bip32_path_t path = {};
  size_t test_cases = sizeof(bip32path_set) / sizeof(test_bip32path_t);
  for (size_t i = 0; i < test_cases; i++) {
    printf("bip32 path: %s\n", bip32path_set[i].str);
    int ret = slip10_parse_path(bip32path_set[i].str, &path);
    TEST_ASSERT(ret == bip32path_set[i].err);
    if (ret == 0) {
      TEST_ASSERT(bip32path_set[i].path_len == (size_t)path.len);
      TEST_ASSERT_EQUAL_MEMORY(bip32path_set[i].exp_path, path.path, path.len);
    }
  }
}

void test_derive_key_from_path() {
  byte_t tmp_seed[64] = {};
  slip10_key_t key = {};
  byte_t tmp_pub[SLIP10_PUBLIC_KEY_BYTES] = {};

  for (size_t i = 0; i < sizeof(slip10_set) / sizeof(test_slip10_t); i++) {
    printf("slip10: %s, %s\n", slip10_set[i].seed, slip10_set[i].path);
    size_t seed_len = strlen(slip10_set[i].seed) / 2;
    // hex seed to bin seed
    TEST_ASSERT(hex_2_bin(slip10_set[i].seed, strlen(slip10_set[i].seed), NULL, tmp_seed, seed_len) == 0);

    // key derivation
    int ret = slip10_key_from_path(tmp_seed, seed_len, slip10_set[i].path, ED25519_CURVE, &key);
    TEST_ASSERT(ret == slip10_set[i].err);

    if (ret == 0) {
      // validating chain code
      TEST_ASSERT_EQUAL_MEMORY(slip10_set[i].chain_code, key.chain_code, SLIP10_CHAIN_CODE_BYTES);
      // validating private key
      TEST_ASSERT_EQUAL_MEMORY(slip10_set[i].private, key.key, SLIP10_PRIVATE_KEY_BYTES);
      // validating public key
      TEST_ASSERT(slip10_public_key(ED25519_CURVE, &key, tmp_pub) == 0);
      TEST_ASSERT_EQUAL_MEMORY(slip10_set[i].public, tmp_pub, SLIP10_PUBLIC_KEY_BYTES);
    }
  }
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_bip32path);
  RUN_TEST(test_derive_key_from_path);

  return UNITY_END();
}
