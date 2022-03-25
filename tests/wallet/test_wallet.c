// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "core/address.h"
#include "unity/unity.h"
#include "wallet/wallet.h"

void setUp(void) {}

void tearDown(void) {}

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

void test_wallet_ed25519_address() {
  address_t tmp_addr = {};
  char bech32_addr[65] = {};
  byte_t exp_seed[] = {0x65, 0xD3, 0x78, 0xF2, 0x6A, 0x10, 0x13, 0x66, 0xD2, 0xB2, 0xBC, 0x98, 0x2D, 0xE1, 0x28, 0x38,
                       0x2F, 0x26, 0x2,  0x5,  0xA8, 0xB9, 0x92, 0x66, 0xFD, 0xCE, 0xE1, 0x4C, 0xC1, 0x2F, 0x46, 0x80,
                       0xEB, 0x66, 0x17, 0x1C, 0x27, 0xBE, 0x1,  0x6,  0x6C, 0x3E, 0xA3, 0xC,  0x9C, 0xB,  0x87, 0xE2,
                       0x7F, 0xB9, 0xF,  0x8C, 0xAB, 0x9A, 0xC7, 0xB8, 0xE2, 0x5,  0xF2, 0x59, 0xD2, 0x75, 0x24, 0xF};
  byte_t exp_pubkey[ED25519_PUBKEY_BYTES] = {0x50, 0xA3, 0x5A, 0x5A, 0xD3, 0x9C, 0x89, 0x9C, 0x2A, 0x42, 0x26,
                                             0x1F, 0x6,  0x87, 0x52, 0x24, 0x74, 0x68, 0x3E, 0x2F, 0x21, 0x4B,
                                             0xB3, 0x2A, 0x5C, 0x38, 0xD1, 0x6,  0x3,  0x57, 0x43, 0x58};
  char exp_bech32[] = "iota1qpg2xkj66wwgn8p2ggnp7p582gj8g6p79us5hve2tsudzpsr2ap4skprwjg";

  iota_wallet_t* w = wallet_create(test_mnemonic, "", 0);
  TEST_ASSERT(wallet_ed25519_address_from_index(w, false, 0, &tmp_addr) == 0);
  TEST_ASSERT_EQUAL_MEMORY(exp_pubkey, tmp_addr.address, sizeof(exp_pubkey));
  TEST_ASSERT_EQUAL_MEMORY(exp_seed, w->seed, sizeof(exp_seed));

  TEST_ASSERT(address_to_bech32(&tmp_addr, "iota", bech32_addr, sizeof(bech32_addr)) == 0);
  TEST_ASSERT_EQUAL_STRING(exp_bech32, bech32_addr);

  wallet_destroy(w);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_wallet_creation);
  RUN_TEST(test_wallet_ed25519_address);

  return UNITY_END();
}
