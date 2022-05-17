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

// replace this with your mnemonic string
static char const* const test_mnemonic =
    "acoustic trophy damage hint search taste love bicycle foster cradle brown govern endless depend situate athlete "
    "pudding blame question genius transfer van random vast";
uint32_t const sender_addr_index = 0;      // address index of a sender
uint32_t const state_ctrl_addr_index = 1;  // address index of a state controller
uint32_t const govern_addr_index = 2;      // address index of a governor

uint64_t const amount = 1;  // transfer 1Mi from a sender to a receiver address

static int get_address_and_keypair(iota_wallet_t* w, bool change, uint32_t index, address_t* addr,
                                   ed25519_keypair_t* keypair) {
  char addr_path[IOTA_ACCOUNT_PATH_MAX] = {};

  if (wallet_ed25519_address_from_index(w, change, index, addr) != 0) {
    printf("[%s:%d] get sender address failed\n", __func__, __LINE__);
    return -1;
  }

  if (get_address_path(w, change, index, addr_path, sizeof(addr_path)) != 0) {
    printf("[%s:%d] can not derive address path from seed and path\n", __func__, __LINE__);
    return -1;
  }

  if (address_keypair_from_path(w->seed, sizeof(w->seed), addr_path, keypair) != 0) {
    printf("[%s:%d] get address keypair failed\n", __func__, __LINE__);
    return -1;
  }

  return 0;
}

int main(void) {
  iota_wallet_t* w = wallet_create(test_mnemonic, "", SLIP44_COIN_TYPE_IOTA, 0);
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
  ed25519_keypair_t sender_keypair, state_ctrl_keypair, govern_keypair;
  if (get_address_and_keypair(w, false, sender_addr_index, &sender_addr, &sender_keypair) != 0) {
    printf("Failed to generate a sender address and private key from an index!\n");
    wallet_destroy(w);
    return -1;
  }
  if (get_address_and_keypair(w, false, state_ctrl_addr_index, &state_ctrl_addr, &state_ctrl_keypair) != 0) {
    printf("Failed to generate a state controller address and private key from an index!\n");
    wallet_destroy(w);
    return -1;
  }
  if (get_address_and_keypair(w, false, govern_addr_index, &govern_addr, &govern_keypair) != 0) {
    printf("Failed to generate a governor address and private key from an index!\n");
    wallet_destroy(w);
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
  printf("Sending transaction message to the Tangle...\n");

  res_send_message_t msg_res = {};
  byte_t output_id[IOTA_OUTPUT_ID_BYTES] = {0};
  if (wallet_alias_create_transaction(w, &sender_addr, &sender_keypair, amount * Mi, &state_ctrl_addr, &govern_addr,
                                      output_id, &msg_res) != 0) {
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
  sleep(10);

  // calculate alias Id
  address_t alias_addr = {0};
  if (alias_address_from_output(output_id, sizeof(output_id), &alias_addr) != 0) {
    printf("Can not create alias address from output Id!\n");
    wallet_destroy(w);
    return -1;
  }

  char bech32_alias[BIN_TO_HEX_STR_BYTES(ADDRESS_MAX_BYTES)] = {};
  if (address_to_bech32(&alias_addr, w->bech32HRP, bech32_alias, sizeof(bech32_alias)) != 0) {
    printf("Failed converting alias address to bech32 format!\n");
    wallet_destroy(w);
    return -1;
  }
  printf("Alias address: %s\n", bech32_sender);

  // create a second transaction with an actual alias ID
  if (wallet_alias_state_transition_transaction(w, alias_addr.address, output_id, &state_ctrl_addr, &state_ctrl_keypair,
                                                &govern_addr, &msg_res) != 0) {
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
