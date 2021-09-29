// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>
#include <unity/unity.h>

#include "wallet/bip39.h"
#include "wallet/wallet.h"

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
    hex_2_bin(vectors[i].ent, entropy_str_len, entropy, sizeof(entropy));
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
  for (ms_lan_t lan = MS_LAN_KO; lan <= MS_LAN_PT; lan++) {
    printf("validating BIP39 language ID %d...\n", lan);
    for (size_t i = 0; i < sizeof(vectors) / sizeof(ms_vectors_t); i++) {
      printf("\tBIP39 vector[%zu]: %s\n", i, vectors[i].ent);
      // encode
      size_t entropy_str_len = strlen(vectors[i].ent);
      size_t entropy_bin_len = entropy_str_len / 2;
      TEST_ASSERT(hex_2_bin(vectors[i].ent, entropy_str_len, entropy, sizeof(entropy)) == 0);
      TEST_ASSERT(mnemonic_encode(entropy, entropy_bin_len, lan, ms_out, MS_BUF_SIZE) == 0);
      printf("\t%s\n", ms_out);
      // decode
      size_t len = mnemonic_decode(ms_out, lan, out_ent, sizeof(out_ent));
      TEST_ASSERT(len != 0);
      // we don't check the ms but validate encode/decode entropy
      TEST_ASSERT_EQUAL_MEMORY(entropy, out_ent, entropy_bin_len);
    }
  }
}

void test_bip39_seed() {
#if defined(CRYPTO_USE_OPENSSL) || defined(CYRPTO_USE_MBEDTLS)
  byte_t seed[64] = {};
  byte_t exp_seed[64] = {};
  for (size_t i = 0; i < sizeof(vectors) / sizeof(ms_vectors_t); i++) {
    TEST_ASSERT(mnemonic_to_seed(vectors[i].ms, "TREZOR", seed, sizeof(seed)) == 0);
    hex_2_bin(vectors[i].seed, strlen(vectors[i].seed), exp_seed, sizeof(exp_seed));
    TEST_ASSERT_EQUAL_MEMORY(exp_seed, seed, sizeof(exp_seed));
  }
#else
  // TODO
  printf("TODO\n");
#endif
}

static char const* const test_mnemonic =
    "acoustic trophy damage hint search taste love bicycle foster cradle brown govern endless depend situate athlete "
    "pudding blame question genius transfer van random vast";

void test_wallet_creation() {
  // create wallet with mnemonic
  iota_wallet_t* w = wallet_create(test_mnemonic, "", 0);
  TEST_ASSERT_NOT_NULL(w);
  wallet_destroy(w);
  w = NULL;

  w = wallet_create(NULL, NULL, 0);
  TEST_ASSERT_NULL(w);
  wallet_destroy(w);

  w = wallet_create(NULL, "", 0);
  TEST_ASSERT_NOT_NULL(w);
  wallet_destroy(w);
}

void test_wallet_address() {
  byte_t tmp_addr[ED25519_ADDRESS_BYTES] = {};
  char bech32_addr[128] = {};
  byte_t exp_seed[] = {0x65, 0xD3, 0x78, 0xF2, 0x6A, 0x10, 0x13, 0x66, 0xD2, 0xB2, 0xBC, 0x98, 0x2D, 0xE1, 0x28, 0x38,
                       0x2F, 0x26, 0x2,  0x5,  0xA8, 0xB9, 0x92, 0x66, 0xFD, 0xCE, 0xE1, 0x4C, 0xC1, 0x2F, 0x46, 0x80,
                       0xEB, 0x66, 0x17, 0x1C, 0x27, 0xBE, 0x1,  0x6,  0x6C, 0x3E, 0xA3, 0xC,  0x9C, 0xB,  0x87, 0xE2,
                       0x7F, 0xB9, 0xF,  0x8C, 0xAB, 0x9A, 0xC7, 0xB8, 0xE2, 0x5,  0xF2, 0x59, 0xD2, 0x75, 0x24, 0xF};
  byte_t exp_addr[ED25519_ADDRESS_BYTES] = {0x50, 0xA3, 0x5A, 0x5A, 0xD3, 0x9C, 0x89, 0x9C, 0x2A, 0x42, 0x26,
                                            0x1F, 0x6,  0x87, 0x52, 0x24, 0x74, 0x68, 0x3E, 0x2F, 0x21, 0x4B,
                                            0xB3, 0x2A, 0x5C, 0x38, 0xD1, 0x6,  0x3,  0x57, 0x43, 0x58};
  char exp_bech32[] = "iota1qpg2xkj66wwgn8p2ggnp7p582gj8g6p79us5hve2tsudzpsr2ap4skprwjg";

  iota_wallet_t* w = wallet_create(test_mnemonic, "", 0);
  wallet_address_from_index(w, false, 0, tmp_addr);
  TEST_ASSERT_EQUAL_MEMORY(exp_addr, tmp_addr, sizeof(exp_addr));
  TEST_ASSERT_EQUAL_MEMORY(exp_seed, w->seed, sizeof(exp_seed));

  wallet_bech32_from_index(w, false, 0, bech32_addr);
  TEST_ASSERT_EQUAL_STRING(exp_bech32, bech32_addr);

  wallet_destroy(w);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_wallet_creation);
  RUN_TEST(test_wallet_address);
  RUN_TEST(test_bip39_vectors);
  RUN_TEST(test_bip39_languages);
  RUN_TEST(test_bip39_seed);

  return UNITY_END();
}