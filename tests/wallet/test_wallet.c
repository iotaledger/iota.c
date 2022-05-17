// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <unistd.h>  // for Linux sleep()

#include "client/api/restful/faucet_enqueue.h"
#include "core/address.h"
#include "core/utils/macros.h"
#include "test_config.h"
#include "unity/unity.h"
#include "wallet/output_basic.h"
#include "wallet/wallet.h"

void setUp(void) {}

void tearDown(void) {}

static char const* const test_mnemonic =
    "acoustic trophy damage hint search taste love bicycle foster cradle brown govern endless depend situate athlete "
    "pudding blame question genius transfer van random vast";

void test_wallet_creation() {
  // create wallet with mnemonic
  iota_wallet_t* w = wallet_create(test_mnemonic, "", SLIP44_COIN_TYPE, 0);
  TEST_ASSERT_NOT_NULL(w);
  wallet_destroy(w);
  w = NULL;

  w = wallet_create(NULL, NULL, SLIP44_COIN_TYPE, 0);
  TEST_ASSERT_NULL(w);
  wallet_destroy(w);

  w = wallet_create(NULL, "", SLIP44_COIN_TYPE, 0);
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

  iota_wallet_t* w = wallet_create(test_mnemonic, "", SLIP44_COIN_TYPE_IOTA, 0);
  TEST_ASSERT(wallet_ed25519_address_from_index(w, false, 0, &tmp_addr) == 0);
  TEST_ASSERT_EQUAL_MEMORY(exp_pubkey, tmp_addr.address, sizeof(exp_pubkey));
  TEST_ASSERT_EQUAL_MEMORY(exp_seed, w->seed, sizeof(exp_seed));

  TEST_ASSERT(address_to_bech32(&tmp_addr, "iota", bech32_addr, sizeof(bech32_addr)) == 0);
  TEST_ASSERT_EQUAL_STRING(exp_bech32, bech32_addr);

  wallet_destroy(w);
}

static int request_token(char const* const addr) {
  iota_client_conf_t ctx = {.host = TEST_FAUCET_HOST, .port = TEST_FAUCET_PORT, .use_tls = TEST_IS_HTTPS};
  res_faucet_enqueue_t res = {};
  // Test bech32 address with invalid len
  TEST_ASSERT_EQUAL_INT(0, req_tokens_to_addr_from_faucet(&ctx, addr, &res));
  if (res.is_error == true) {
    printf("request token err: %s\n", res.u.error->msg);
    return -1;
  } else {
    printf("request token: %s\n", addr);
  }
  return 0;
}

void test_wallet_basic_transfer() {
  iota_wallet_t* w = wallet_create(test_mnemonic, "", SLIP44_COIN_TYPE, 0);
  TEST_ASSERT_NOT_NULL(w);

  // set endpoint and update node info
  TEST_ASSERT(wallet_set_endpoint(w, TEST_NODE_HOST, TEST_NODE_PORT, TEST_IS_HTTPS) == 0);
  TEST_ASSERT(wallet_update_node_config(w) == 0);

  // get address
  address_t sender, receiver;
  TEST_ASSERT(wallet_ed25519_address_from_index(w, false, 0, &sender) == 0);
  TEST_ASSERT(wallet_ed25519_address_from_index(w, false, 1, &receiver) == 0);

  // get sender keypair
  ed25519_keypair_t sender_keypair;
  char addr_path[IOTA_ACCOUNT_PATH_MAX] = {};
  TEST_ASSERT(get_address_path(w, false, 0, addr_path, sizeof(addr_path)) == 0);
  TEST_ASSERT(address_keypair_from_path(w->seed, sizeof(w->seed), addr_path, &sender_keypair) == 0);

  // request token from the fuacet
  char sender_bech32[BIN_TO_HEX_STR_BYTES(ADDRESS_MAX_BYTES)] = {};
  TEST_ASSERT(address_to_bech32(&sender, w->bech32HRP, sender_bech32, sizeof(sender_bech32)) == 0);
  TEST_ASSERT(request_token(sender_bech32) == 0);
  // wait a little bit for getting tokens from faucet
  sleep(3);

  // transfer IOTA tokens
  res_send_message_t msg_res = {};
  // this transfer should be failed due to storage deposit
  int ret = wallet_basic_transaction(w, &sender, &sender_keypair, 212999, &receiver, &msg_res);
  TEST_ASSERT(ret != 0);
  if (ret == 0) {
    if (msg_res.is_error) {
      printf("[%s:%d] Error: %s\n", __func__, __LINE__, msg_res.u.error->msg);
      res_err_free(msg_res.u.error);
    } else {
      printf("[%s:%d] Message ID: %s\n", __func__, __LINE__, msg_res.u.msg_id);
    }
  } else {
    printf("[%s:%d] send message failed\n", __func__, __LINE__);
  }

  // this transfer should be sent to the Tangle
  ret = wallet_basic_transaction(w, &sender, &sender_keypair, 1000000, &receiver, &msg_res);
  TEST_ASSERT(ret == 0);
  if (ret == 0) {
    if (msg_res.is_error) {
      printf("[%s:%d] Error: %s\n", __func__, __LINE__, msg_res.u.error->msg);
      res_err_free(msg_res.u.error);
    } else {
      printf("[%s:%d] Message ID: %s\n", __func__, __LINE__, msg_res.u.msg_id);
    }
  } else {
    printf("[%s:%d] send message failed\n", __func__, __LINE__);
  }

  wallet_destroy(w);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_wallet_creation);
  RUN_TEST(test_wallet_ed25519_address);
#if TEST_TANGLE_ENABLE
  RUN_TEST(test_wallet_basic_transfer);
#endif

  return UNITY_END();
}
