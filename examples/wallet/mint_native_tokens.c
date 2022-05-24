// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/**
 * @brief A simple example of minting a native tokens and sending them to a receiver address using wallet APIs.
 *
 */

#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>  // for Linux sleep()

#include "wallet/output_alias.h"
#include "wallet/output_foundry.h"
#include "wallet/wallet.h"

#define Mi 1000000

#define NODE_HOST "localhost"
#define NODE_PORT 14265
#define NODE_USE_TLS false
#define TEST_COIN_TYPE SLIP44_COIN_TYPE_IOTA

// replace this with your mnemonic string
static char const* const test_mnemonic =
    "acoustic trophy damage hint search taste love bicycle foster cradle brown govern endless depend situate athlete "
    "pudding blame question genius transfer van random vast";
uint32_t const sender_addr_index = 0;      // address index of a sender
uint32_t const state_ctrl_addr_index = 1;  // address index of a state controller
uint32_t const govern_addr_index = 2;      // address index of a governor
uint32_t const receiver_addr_index = 3;    // address index of a receiver of native tokens
uint64_t const amount = 1;                 // transfer 1Mi from a sender to an alias output (address)
static char const* const max_supply_str =
    "1000000000000000000000000000000";                         // maximum supply of newly minted native tokens
static char const* const minted_tokens_str = "1000000000000";  // number of newly minted native tokens

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

  address_t sender_addr, state_ctrl_addr, govern_addr, receiver_addr;
  if (wallet_ed25519_address_from_index(w, false, sender_addr_index, &sender_addr) != 0) {
    printf("Get sender address failed\n");
    return -1;
  }
  if (wallet_ed25519_address_from_index(w, false, state_ctrl_addr_index, &state_ctrl_addr) != 0) {
    printf("Get state controller address failed\n");
    return -1;
  }
  if (wallet_ed25519_address_from_index(w, false, govern_addr_index, &govern_addr) != 0) {
    printf("Get governor address failed!\n");
    return -1;
  }
  if (wallet_ed25519_address_from_index(w, false, receiver_addr_index, &receiver_addr) != 0) {
    printf("Get receiver address failed\n");
    return -1;
  }

  // convert bech32 address to sender address
  char bech32_sender[BIN_TO_HEX_STR_BYTES(ADDRESS_MAX_BYTES)] = {};
  if (address_to_bech32(&sender_addr, w->bech32HRP, bech32_sender, sizeof(bech32_sender)) != 0) {
    printf("Failed converting sender address to bech32 format!\n");
    wallet_destroy(w);
    return -1;
  }

  // convert state controller address to bech32 format
  char bech32_state_ctrl[BIN_TO_HEX_STR_BYTES(ADDRESS_MAX_BYTES)] = {};
  if (address_to_bech32(&state_ctrl_addr, w->bech32HRP, bech32_state_ctrl, sizeof(bech32_state_ctrl)) != 0) {
    printf("Failed converting state controller address to bech32 format!\n");
    wallet_destroy(w);
    return -1;
  }

  // convert governor address to bech32 format
  char bech32_govern[BIN_TO_HEX_STR_BYTES(ADDRESS_MAX_BYTES)] = {};
  if (address_to_bech32(&govern_addr, w->bech32HRP, bech32_govern, sizeof(bech32_govern)) != 0) {
    printf("Failed converting governor address to bech32 format!\n");
    wallet_destroy(w);
    return -1;
  }

  // convert receiver address to bech32 format
  char bech32_receiver[BIN_TO_HEX_STR_BYTES(ADDRESS_MAX_BYTES)] = {};
  if (address_to_bech32(&receiver_addr, w->bech32HRP, bech32_receiver, sizeof(bech32_receiver)) != 0) {
    printf("Failed converting receiver address to bech32 format!\n");
    wallet_destroy(w);
    return -1;
  }

  printf("Sender address: %s\n", bech32_sender);
  printf("State controller address: %s\n", bech32_state_ctrl);
  printf("Governor address: %s\n", bech32_govern);
  printf("Receiver address: %s\n", bech32_receiver);

  // create alias output
  printf("Sending create alias transaction message to the Tangle...\n");

  res_send_message_t msg_res = {};
  address_t alias_addr = {0};
  if (wallet_alias_output_create(w, false, sender_addr_index, amount * Mi, &state_ctrl_addr, &govern_addr, 0,
                                 &alias_addr, &msg_res) != 0) {
    printf("Sending message to the Tangle failed!\n");
    wallet_destroy(w);
    return -1;
  }

  if (msg_res.is_error) {
    printf("Error: %s\n", msg_res.u.error->msg);
    res_err_free(msg_res.u.error);
    wallet_destroy(w);
    return -1;
  }

  printf("Message successfully sent.\n");
  printf("Message ID: %s\n", msg_res.u.msg_id);

  // wait for a message to be included into a tangle
  printf("Waiting for message confirmation...\n");
  sleep(15);

  // convert alias address to bech32 format
  char bech32_alias[BIN_TO_HEX_STR_BYTES(ADDRESS_MAX_BYTES)] = {};
  if (address_to_bech32(&alias_addr, w->bech32HRP, bech32_alias, sizeof(bech32_alias)) != 0) {
    printf("Failed converting alias address to bech32 format!\n");
    wallet_destroy(w);
    return -1;
  }
  printf("Alias address: %s\n", bech32_alias);

  uint256_t* max_supply = uint256_from_str(max_supply_str);
  uint256_t* minted_tokens = uint256_from_str(minted_tokens_str);

  printf("\nMinting native tokens:\n");
  printf("Maximum supply: %s\n", max_supply_str);
  printf("Minted tokens: %s\n", minted_tokens_str);

  // mint native tokens
  printf("Sending mint native tokens transaction message to the Tangle...\n");

  if (wallet_foundry_output_mint_native_tokens(w, &alias_addr, false, state_ctrl_addr_index, &govern_addr,
                                               &receiver_addr, max_supply, minted_tokens, 1, 1, &msg_res) != 0) {
    printf("Sending message to the Tangle failed!\n");
    uint256_free(max_supply);
    uint256_free(minted_tokens);
    wallet_destroy(w);
    return -1;
  }

  uint256_free(max_supply);
  uint256_free(minted_tokens);

  if (msg_res.is_error) {
    printf("Error: %s\n", msg_res.u.error->msg);
    res_err_free(msg_res.u.error);
    wallet_destroy(w);
    return -1;
  }

  printf("Message successfully sent.\n");
  printf("Message ID: %s\n", msg_res.u.msg_id);

  wallet_destroy(w);

  return 0;
}
