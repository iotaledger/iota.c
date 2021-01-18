// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <unity/unity.h>

#include "wallet/wallet.h"

void test_wallet_api() {
  byte_t seed[] = {0xe5, 0x7f, 0xb7, 0x50, 0xf3, 0xa3, 0xa6, 0x79, 0x69, 0xec, 0xe5, 0xbd, 0x9a, 0xe7, 0xee, 0xf5,
                   0xb2, 0x25, 0x6a, 0x81, 0x8b, 0x2a, 0xac, 0x45, 0x89, 0x41, 0xf7, 0x27, 0x49, 0x85, 0xa4, 0x10};

  iota_wallet_t* wallet = wallet_create(seed, "");
  TEST_ASSERT_NULL(wallet);
  // Bip44 Paths: 44,4128,Account,Change
  wallet = wallet_create(seed, "m/44'/4218'");
  TEST_ASSERT_NULL(wallet);
  wallet = wallet_create(seed, "m/44'/4218'/0");
  TEST_ASSERT_NULL(wallet);
  wallet = wallet_create(seed, "m/44'/4218'/0'");
  TEST_ASSERT_NULL(wallet);
  wallet = wallet_create(seed, "m/44'/4218'/0'/");
  TEST_ASSERT_NULL(wallet);
  wallet = wallet_create(seed, "m/44'/4218'/0'/0");
  TEST_ASSERT_NULL(wallet);
  wallet = wallet_create(seed, "m/44'/4218'/0'/0'");
  TEST_ASSERT_NOT_NULL(wallet);

  wallet_destroy(wallet);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_wallet_api);

  return UNITY_END();
}