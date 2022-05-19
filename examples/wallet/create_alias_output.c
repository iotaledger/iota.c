// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/**
 * @brief A simple example of creating a transaction with an alias output using wallet APIs.
 *
 */

#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>  // for Linux sleep()

#include "wallet/output_alias.h"
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
uint64_t const amount = 1;                 // transfer 1Mi from a sender to a receiver address

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

  address_t sender_addr, state_ctrl_addr, govern_addr;
  if (wallet_ed25519_address_from_index(w, false, sender_addr_index, &sender_addr) != 0) {
    printf("[%s:%d] get sender address failed\n", __func__, __LINE__);
    return -1;
  }
  if (wallet_ed25519_address_from_index(w, false, state_ctrl_addr_index, &state_ctrl_addr) != 0) {
    printf("[%s:%d] get state controller address failed\n", __func__, __LINE__);
    return -1;
  }
  if (wallet_ed25519_address_from_index(w, false, govern_addr_index, &govern_addr) != 0) {
    printf("[%s:%d] get governor address failed\n", __func__, __LINE__);
    return -1;
  }

  // convert sender address to bech32 format
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

  printf("Sender address: %s\n", bech32_sender);
  printf("State controller address: %s\n", bech32_state_ctrl);
  printf("Governor address: %s\n", bech32_govern);
  printf("Amount to send: %" PRIu64 "\n", amount * Mi);

  // create alias output
  printf("Sending create alias transaction message to the Tangle...\n");

  res_send_message_t msg_res = {};
  address_t alias_addr = {0};
  if (wallet_alias_output_create(w, false, sender_addr_index, amount * Mi, &state_ctrl_addr, &govern_addr, &alias_addr,
                                 &msg_res) != 0) {
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

  // send state transition transaction
  printf("Sending alias state transition transaction message to the Tangle...\n");

  // create a second transaction with an actual alias ID
  if (wallet_alias_output_state_transition(w, alias_addr.address, false, state_ctrl_addr_index, &govern_addr,
                                           &msg_res) != 0) {
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

  // send alias destroy transaction
  printf("Sending alias destroy transaction message to the Tangle...\n");

  // create a third transaction to destroy alias output
  if (wallet_alias_output_destroy(w, alias_addr.address, false, govern_addr_index, &sender_addr, &msg_res) != 0) {
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

  wallet_destroy(w);

  return 0;
}
