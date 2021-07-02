// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>
#include <unity/unity.h>

#include "wallet/wallet.h"

static const byte_t seed[] = {0xe5, 0x7f, 0xb7, 0x50, 0xf3, 0xa3, 0xa6, 0x79, 0x69, 0xec, 0xe5,
                              0xbd, 0x9a, 0xe7, 0xee, 0xf5, 0xb2, 0x25, 0x6a, 0x81, 0x8b, 0x2a,
                              0xac, 0x45, 0x89, 0x41, 0xf7, 0x27, 0x49, 0x85, 0xa4, 0x10};
typedef struct {
  uint32_t index;  // the index is limited by slip10 spec, the maximun is 2147483646 (1 << 31U).
  byte_t addr[ED25519_ADDRESS_BYTES];
} addr_validater_t;

static const addr_validater_t exp_addresses[] = {
    {0, {0x51, 0x55, 0x82, 0xFE, 0x64, 0x8B, 0xF,  0x10, 0xA2, 0xB2, 0xA1, 0xB9, 0x1D, 0x75, 0x2,  0x19,
         0xC,  0x97, 0x9B, 0xAA, 0xBF, 0xEE, 0x85, 0xB6, 0xBB, 0xB5, 0x2,  0x6,  0x92, 0xE5, 0x5D, 0x16}},
    {3, {0xBC, 0x98, 0x1B, 0xEA, 0x99, 0x24, 0xFE, 0x92, 0x1C, 0xF4, 0x1D, 0x7D, 0x8C, 0x5A, 0xE4, 0x8F,
         0xB4, 0x53, 0x31, 0x3F, 0xE4, 0xA6, 0xA1, 0xD6, 0xE8, 0x8A, 0xC5, 0xAE, 0x42, 0xF0, 0x47, 0x7A}},
    {5000, {0x6D, 0x9A, 0x35, 0xE9, 0x8E, 0x27, 0x84, 0xA0, 0x43, 0xD5, 0x55, 0xE6, 0xB1, 0x71, 0xC7, 0x97,
            0xB0, 0x1,  0xC2, 0xA1, 0x49, 0x5B, 0xC4, 0x9B, 0xCE, 0x3B, 0xF0, 0xAB, 0xBD, 0xF7, 0x39, 0x77}},
    {10000, {0xB1, 0x77, 0xFC, 0xCC, 0x51, 0x15, 0x3E, 0x63, 0x8F, 0x6D, 0xD6, 0x28, 0xA4, 0xA7, 0x3F, 0x11,
             0xA5, 0x94, 0x8,  0xF3, 0xEA, 0x50, 0x7F, 0x8A, 0x58, 0xA7, 0x1F, 0xA1, 0x6D, 0x23, 0x79, 0xA3}},
    {2147483646, {0x48, 0xE0, 0x32, 0x25, 0x60, 0x8,  0x98, 0x78, 0x4B, 0x82, 0xDB, 0xD7, 0x2D, 0xA1, 0x45, 0x8B,
                  0xDB, 0xF6, 0x33, 0x0,  0xE2, 0x9A, 0x2,  0x3,  0xC2, 0x68, 0xE5, 0x5B, 0xF4, 0xD0, 0x5E, 0x8F}}};

void setUp(void) {}

void tearDown(void) {}

void test_wallet_api() {
  // path validation
  iota_wallet_t* wallet = wallet_create(seed, "");
  TEST_ASSERT_NULL(wallet);
  // invalid parameter
  wallet = wallet_create(NULL, "m/44'/4218'");
  TEST_ASSERT_NULL(wallet);
  // invalid path format
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
  // Bip44 path format: 44,4128,Account,Change
  // 2 addresses will be used in this wallet
  wallet = wallet_create(seed, "m/44'/4218'/0'/0'");
  TEST_ASSERT_NOT_NULL(wallet);

  // address validation
  byte_t addr[ED25519_ADDRESS_BYTES] = {};
  for (size_t i = 0; i < sizeof(exp_addresses) / sizeof(addr_validater_t); i++) {
    TEST_ASSERT(wallet_address_by_index(wallet, exp_addresses[i].index, addr) == 0);
    TEST_ASSERT_EQUAL_MEMORY(exp_addresses[i].addr, addr, ED25519_ADDRESS_BYTES);
    dump_hex_str(addr, ED25519_ADDRESS_BYTES);
  }

  // testnet with default port number
  TEST_ASSERT(wallet_set_endpoint(wallet, "api.lb-0.testnet.chrysalis2.com", 443, true) == 0);

  wallet_destroy(wallet);
}

void test_wallet_api_with_node() {
  char msg_id[IOTA_MESSAGE_ID_HEX_BYTES + 1] = {};
  // create a wallet account
  iota_wallet_t* wallet = wallet_create(seed, "m/44'/4218'/0'/0'");
  TEST_ASSERT_NOT_NULL(wallet);

  // get address of index 0
  byte_t addr[ED25519_ADDRESS_BYTES] = {};
  TEST_ASSERT(wallet_address_by_index(wallet, 0, addr) == 0);

  uint64_t balance_index = 0, balance_addr = 0;
  TEST_ASSERT(wallet_balance_by_index(wallet, 0, &balance_index) == 0);
  // printf("balance by index: %"PRIu64"\n", balance_index);
  TEST_ASSERT(wallet_balance_by_address(wallet, addr, &balance_addr) == 0);
  // printf("balance by addr: %"PRIu64"\n", balance_addr);
  TEST_ASSERT(balance_addr == balance_index);

  // send indexation message
  byte_t recv_addr[ED25519_ADDRESS_BYTES] = {};
  TEST_ASSERT(wallet_address_by_index(wallet, 1, recv_addr) == 0);
  byte_t index_data[] = {0x73, 0x65, 0x6e, 0x64, 0x20, 0x66, 0x72, 0x6f,
                         0x6d, 0x20, 0x69, 0x6f, 0x74, 0x61, 0x2e, 0x63};
  TEST_ASSERT(wallet_send(wallet, 0, NULL, 0, "iota.c", index_data, sizeof(index_data), msg_id, sizeof(msg_id)) == 0);

  // send transaction with unsificent balance
  TEST_ASSERT(wallet_send(wallet, 0, recv_addr, 2779530283277760, NULL, NULL, 0, msg_id, sizeof(msg_id)) != 0);
  // send transaction without indexation
  TEST_ASSERT(wallet_send(wallet, 0, recv_addr, 1000000, NULL, NULL, 0, msg_id, sizeof(msg_id)) == 0);
  // send transaction with indexation
  TEST_ASSERT(wallet_send(wallet, 0, recv_addr, 1000000, "iota.c", index_data, sizeof(index_data), msg_id,
                          sizeof(msg_id)) == 0);

  wallet_destroy(wallet);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_wallet_api);
  // tested on alphanet
  // RUN_TEST(test_wallet_api_with_node);

  return UNITY_END();
}