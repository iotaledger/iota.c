// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/**
 * @brief A simple example of sending a native tokens to the Tangle using wallet APIs.
 *
 */

#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>  // for Linux sleep()

#include "core/models/outputs/output_foundry.h"
#include "core/utils/bech32.h"
#include "wallet/output_alias.h"
#include "wallet/output_basic.h"
#include "wallet/output_foundry.h"
#include "wallet/wallet.h"

#define Mi 1000000

#define NODE_HOST "localhost"
#define NODE_PORT 14265
#define NODE_USE_TLS false
#define TEST_COIN_TYPE SLIP44_COIN_TYPE_IOTA

// replace this with your mnemonic string
static char const* const test_mnemonic =
    "vast trophy damage hint search taste love bicycle foster cradle brown govern endless depend situate athlete "
    "pudding blame question genius transfer van random vast";
uint32_t const sender_addr_index = 0;      // address index of a sender
uint32_t const state_ctrl_addr_index = 1;  // address index of a state controller
uint32_t const govern_addr_index = 2;      // address index of a governor
uint32_t const receiver_1_addr_index = 3;  // address index of a receiver of native tokens from alias output
uint32_t const receiver_2_addr_index = 4;  // address index of a receiver of native tokens from a basic output
uint64_t const amount = 1;                 // transfer 1Mi from a sender to an alias output (address)
static char const* const max_supply_str =
    "1000000000000000000000000000000";                         // maximum supply of newly minted native tokens
static char const* const minted_tokens_str = "1000000000000";  // number of newly minted native tokens
char const* const native_token_amount = "1000";  // transfer 1000 native tokens from a sender to a receiver address

int main(void) {
  iota_wallet_t* w = wallet_create(test_mnemonic, "", TEST_COIN_TYPE, 0);
  if (!w) {
    printf("Failed to create a wallet object!\n");
    return -1;
  }

  if (wallet_set_endpoint(w, NODE_HOST, NODE_PORT, NODE_USE_TLS) != 0) {
    printf("Failed to set a wallet endpoint!\n");
    wallet_destroy(w);
    return -1;
  }

  if (wallet_update_node_config(w) != 0) {
    printf("Failed to update a node configuration!\n");
    wallet_destroy(w);
    return -1;
  }

  address_t sender_addr, state_ctrl_addr, govern_addr, receiver_1_addr, receiver_2_addr;
  if (wallet_ed25519_address_from_index(w, false, sender_addr_index, &sender_addr) != 0) {
    printf("Get sender address failed\n");
    wallet_destroy(w);
    return -1;
  }
  if (wallet_ed25519_address_from_index(w, false, state_ctrl_addr_index, &state_ctrl_addr) != 0) {
    printf("Get state controller address failed\n");
    wallet_destroy(w);
    return -1;
  }
  if (wallet_ed25519_address_from_index(w, false, govern_addr_index, &govern_addr) != 0) {
    printf("Get governor address failed!\n");
    wallet_destroy(w);
    return -1;
  }
  if (wallet_ed25519_address_from_index(w, false, receiver_1_addr_index, &receiver_1_addr) != 0) {
    printf("Get receiver 1 address failed\n");
    wallet_destroy(w);
    return -1;
  }
  if (wallet_ed25519_address_from_index(w, false, receiver_2_addr_index, &receiver_2_addr) != 0) {
    printf("Get receiver 2 address failed\n");
    wallet_destroy(w);
    return -1;
  }

  // convert bech32 address to sender address
  char bech32_sender[BECH32_MAX_STRING_LEN + 1] = {};
  if (address_to_bech32(&sender_addr, w->bech32HRP, bech32_sender, sizeof(bech32_sender)) != 0) {
    printf("Failed converting sender address to bech32 format!\n");
    wallet_destroy(w);
    return -1;
  }

  // convert state controller address to bech32 format
  char bech32_state_ctrl[BECH32_MAX_STRING_LEN + 1] = {};
  if (address_to_bech32(&state_ctrl_addr, w->bech32HRP, bech32_state_ctrl, sizeof(bech32_state_ctrl)) != 0) {
    printf("Failed converting state controller address to bech32 format!\n");
    wallet_destroy(w);
    return -1;
  }

  // convert governor address to bech32 format
  char bech32_govern[BECH32_MAX_STRING_LEN + 1] = {};
  if (address_to_bech32(&govern_addr, w->bech32HRP, bech32_govern, sizeof(bech32_govern)) != 0) {
    printf("Failed converting governor address to bech32 format!\n");
    wallet_destroy(w);
    return -1;
  }

  // convert receiver 1 address to bech32 format
  char bech32_receiver_1[BECH32_MAX_STRING_LEN + 1] = {};
  if (address_to_bech32(&receiver_1_addr, w->bech32HRP, bech32_receiver_1, sizeof(bech32_receiver_1)) != 0) {
    printf("Failed converting receiver 1 address to bech32 format!\n");
    wallet_destroy(w);
    return -1;
  }

  // convert receiver 2 address to bech32 format
  char bech32_receiver_2[BECH32_MAX_STRING_LEN + 1] = {};
  if (address_to_bech32(&receiver_1_addr, w->bech32HRP, bech32_receiver_2, sizeof(bech32_receiver_2)) != 0) {
    printf("Failed converting receiver 2 address to bech32 format!\n");
    wallet_destroy(w);
    return -1;
  }

  printf("Creating alias address:\n");
  printf("Sender address: %s\n", bech32_sender);
  printf("State controller address: %s\n", bech32_state_ctrl);
  printf("Governor address: %s\n", bech32_govern);
  printf("Receiver 1 address: %s\n", bech32_receiver_1);

  // create alias output
  printf("\nSending create alias transaction block to the Tangle...\n");

  res_send_block_t blk_res = {};
  address_t alias_addr = {0};
  if (wallet_alias_output_create(w, false, sender_addr_index, amount * Mi, &state_ctrl_addr, &govern_addr, 0,
                                 &alias_addr, &blk_res) != 0) {
    printf("Sending block to the Tangle failed!\n");
    wallet_destroy(w);
    return -1;
  }

  if (blk_res.is_error) {
    printf("Error: %s\n", blk_res.u.error->msg);
    res_err_free(blk_res.u.error);
    wallet_destroy(w);
    return -1;
  }

  printf("Block successfully sent.\n");
  printf("Block ID: %s\n", blk_res.u.blk_id);

  // wait for a block to be included into a tangle
  printf("Waiting for block confirmation...\n");
  sleep(10);

  // convert alias address to bech32 format
  char bech32_alias[BECH32_MAX_STRING_LEN + 1] = {};
  if (address_to_bech32(&alias_addr, w->bech32HRP, bech32_alias, sizeof(bech32_alias)) != 0) {
    printf("Failed converting alias address to bech32 format!\n");
    wallet_destroy(w);
    return -1;
  }
  printf("Alias address: %s\n", bech32_alias);

  uint256_t* max_supply = uint256_from_str(max_supply_str);
  uint256_t* minted_tokens = uint256_from_str(minted_tokens_str);
  uint32_t serial_number = 1;
  uint32_t foundry_counter = 1;

  printf("\nMinting native tokens:\n");
  printf("Maximum supply: %s\n", max_supply_str);
  printf("Minted tokens: %s\n", minted_tokens_str);

  // mint native tokens
  printf("\nSending mint native tokens transaction block to the Tangle...\n");

  if (wallet_foundry_output_mint_native_tokens(w, &alias_addr, false, state_ctrl_addr_index, &govern_addr,
                                               &receiver_1_addr, max_supply, minted_tokens, serial_number,
                                               foundry_counter, &blk_res) != 0) {
    printf("Sending block to the Tangle failed!\n");
    uint256_free(max_supply);
    uint256_free(minted_tokens);
    wallet_destroy(w);
    return -1;
  }

  uint256_free(max_supply);
  uint256_free(minted_tokens);

  if (blk_res.is_error) {
    printf("Error: %s\n", blk_res.u.error->msg);
    res_err_free(blk_res.u.error);
    wallet_destroy(w);
    return -1;
  }

  printf("Block successfully sent.\n");
  printf("Block ID: %s\n", blk_res.u.blk_id);

  // wait for a block to be included into a tangle
  printf("Waiting for block confirmation...\n");
  sleep(10);

  // calculate native token ID
  byte_t token_id[NATIVE_TOKEN_ID_BYTES] = {0};
  size_t addr_ser_len = address_serialized_len(&alias_addr);
  if (address_serialize(&alias_addr, token_id, sizeof(token_id)) != addr_ser_len) {
    printf("[%s:%d] can not serialize address\n", __func__, __LINE__);
    wallet_destroy(w);
    return -1;
  }
  memcpy(token_id + ADDRESS_SERIALIZED_BYTES, &serial_number, sizeof(serial_number));
  memset(token_id + addr_ser_len + sizeof(serial_number), (uint8_t)SIMPLE_TOKEN_SCHEME, sizeof(uint8_t));

  printf("\nSending native tokens:\n");
  printf("Sender address: %s\n", bech32_receiver_1);
  printf("Receiver address: %s\n", bech32_receiver_2);
  printf("Native token ID: ");
  dump_hex_str(token_id, NATIVE_TOKEN_ID_BYTES);
  printf("Amount to send: %s\n", native_token_amount);

  native_tokens_list_t* native_tokens = native_tokens_new();
  uint256_t* native_tokens_amount = uint256_from_str(native_token_amount);
  if (native_tokens_add(&native_tokens, token_id, native_tokens_amount) != 0) {
    printf("[%s:%d] can not add native token to a list\n", __func__, __LINE__);
    uint256_free(native_tokens_amount);
    wallet_destroy(w);
    return -1;
  }
  uint256_free(native_tokens_amount);

  // transfer native tokens
  printf("\nSending transaction block to the Tangle...\n");
  if (wallet_basic_output_send(w, false, receiver_1_addr_index, 0, native_tokens, &receiver_2_addr, &blk_res) != 0) {
    printf("Sending block to the Tangle failed!\n");
    native_tokens_free(native_tokens);
    wallet_destroy(w);
    return -1;
  }
  native_tokens_free(native_tokens);

  if (blk_res.is_error) {
    printf("Error: %s\n", blk_res.u.error->msg);
    res_err_free(blk_res.u.error);
    wallet_destroy(w);
    return -1;
  }

  printf("Block successfully sent.\n");
  printf("Block ID: %s\n", blk_res.u.blk_id);

  wallet_destroy(w);

  return 0;
}
