// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "core/utils/byte_buffer.h"
#include "unity/unity.h"
#include "wallet/bip39.h"

#include "mnemonic_vectors.h"

// max entropy input size is 32
#define ENT_BUF_LEN 32
// depends on the chosen language
#define MS_BUF_SIZE 1024
// wrt bip39 spec, should be bigger than 33 bytes
#define ENT_OUT_BUF_LEN 64

// buffers used by test_bip39_en and test_bip39_languages
byte_t entropy[ENT_BUF_LEN] = {};
char ms_out[MS_BUF_SIZE] = {};
char ms_zh_out[MS_BUF_SIZE] = {};
byte_t out_ent[ENT_OUT_BUF_LEN] = {};

void setUp(void) {}

void tearDown(void) {}

// validate encode/decode/ms with English
void test_bip39_vectors() {
  for (size_t i = 0; i < sizeof(vectors) / sizeof(ms_vectors_t); i++) {
    printf("validating BIP39 vector[%zu]: %s\n", i, vectors[i].ent);
    // encode
    size_t entropy_str_len = strlen(vectors[i].ent);
    size_t entropy_bin_len = entropy_str_len / 2;
    hex_2_bin(vectors[i].ent, entropy_str_len, NULL, entropy, sizeof(entropy));
    mnemonic_encode(entropy, entropy_bin_len, MS_LAN_EN, ms_out, MS_BUF_SIZE);
    TEST_ASSERT_EQUAL_MEMORY(vectors[i].ms, ms_out, strlen(vectors[i].ms));
    printf("%s\n", ms_out);

    // decode
    size_t len = mnemonic_decode(ms_out, MS_LAN_EN, out_ent, sizeof(out_ent));
    TEST_ASSERT(len != 0);
    TEST_ASSERT_EQUAL_MEMORY(entropy, out_ent, entropy_bin_len);
    // dump_hex_str(out_ent, len);
  }
}

// validate encode/decode with other languages
void test_bip39_languages() {
#ifndef BIP39_ENGLISH_ONLY
  for (ms_lan_t lan = MS_LAN_KO; lan <= MS_LAN_PT; lan++) {
    printf("validating BIP39 language ID %d...\n", lan);
    for (size_t i = 0; i < sizeof(vectors) / sizeof(ms_vectors_t); i++) {
      printf("\tBIP39 vector[%zu]: %s\n", i, vectors[i].ent);
      // encode
      size_t entropy_str_len = strlen(vectors[i].ent);
      size_t entropy_bin_len = entropy_str_len / 2;
      TEST_ASSERT(hex_2_bin(vectors[i].ent, entropy_str_len, NULL, entropy, sizeof(entropy)) == 0);
      TEST_ASSERT(mnemonic_encode(entropy, entropy_bin_len, lan, ms_out, MS_BUF_SIZE) == 0);
      printf("\t%s\n", ms_out);
      // decode
      size_t len = mnemonic_decode(ms_out, lan, out_ent, sizeof(out_ent));
      TEST_ASSERT(len != 0);
      // we don't check the ms but validate encode/decode entropy
      TEST_ASSERT_EQUAL_MEMORY(entropy, out_ent, entropy_bin_len);
    }
  }
#endif
}

void test_bip39_seed() {
  byte_t seed[64] = {};
  byte_t exp_seed[64] = {};
  for (size_t i = 0; i < sizeof(vectors) / sizeof(ms_vectors_t); i++) {
    TEST_ASSERT(mnemonic_to_seed(vectors[i].ms, "TREZOR", seed, sizeof(seed)) == 0);
    hex_2_bin(vectors[i].seed, strlen(vectors[i].seed), NULL, exp_seed, sizeof(exp_seed));
    TEST_ASSERT_EQUAL_MEMORY(exp_seed, seed, sizeof(exp_seed));
  }
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_bip39_vectors);
  RUN_TEST(test_bip39_languages);
  RUN_TEST(test_bip39_seed);

  return UNITY_END();
}
