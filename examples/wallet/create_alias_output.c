// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/**
 * @brief A simple example of creating a transaction with an alias output using wallet APIs.
 *
 */

#include <inttypes.h>
#include <stdio.h>

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
uint32_t const sender_addr_index = 0;            // address index of a sender
uint32_t const state_controller_addr_index = 1;  // address index of a state controller
uint32_t const governor_addr_index = 2;          // address index of a governor

uint64_t const amount = 1;  // transfer 1Mi from a sender to a receiver address

static int get_address_and_keypair(iota_wallet_t* w, bool change, uint32_t index, address_t* addr,
                                   ed25519_keypair_t* keypair) {
  char addr_path[IOTA_ACCOUNT_PATH_MAX] = {};

  if (wallet_ed25519_address_from_index(w, change, index, addr) != 0) {
    printf("[%s:%d] get sender address failed\n", __func__, __LINE__);
    return -1;
  }

  if (get_address_path(w, change, index, addr_path, sizeof(addr_path)) != 0) {
    printf("[%s:%d] Can not derive ed25519 address from seed and path\n", __func__, __LINE__);
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

  address_t sender, state_controller, governor;
  ed25519_keypair_t sender_keypair, state_controller_keypair, governor_keypair;
  if (get_address_and_keypair(w, false, sender_addr_index, &sender, &sender_keypair) != 0) {
    printf("Failed to generate a sender address and private key from an index!\n");
    wallet_destroy(w);
    return -1;
  }
  if (get_address_and_keypair(w, false, state_controller_addr_index, &state_controller, &state_controller_keypair) !=
      0) {
    printf("Failed to generate a sender address and private key from an index!\n");
    wallet_destroy(w);
    return -1;
  }
  if (get_address_and_keypair(w, false, governor_addr_index, &governor, &governor_keypair) != 0) {
    printf("Failed to generate a state controller address and private key from an index!\n");
    wallet_destroy(w);
    return -1;
  }

  // convert sender address to bech32 format
  char bech32_sender[BIN_TO_HEX_STR_BYTES(ADDRESS_MAX_BYTES)] = {};
  if (address_to_bech32(&sender, w->bech32HRP, bech32_sender, sizeof(bech32_sender)) != 0) {
    printf("Failed converting sender address to bech32 format!\n");
    wallet_destroy(w);
    return -1;
  }

  // convert state controller address to bech32 format
  char bech32_state_controller[BIN_TO_HEX_STR_BYTES(ADDRESS_MAX_BYTES)] = {};
  if (address_to_bech32(&state_controller, w->bech32HRP, bech32_state_controller, sizeof(bech32_state_controller)) !=
      0) {
    printf("Failed converting state controller address to bech32 format!\n");
    wallet_destroy(w);
    return -1;
  }

  // convert governor address to bech32 format
  char bech32_governor[BIN_TO_HEX_STR_BYTES(ADDRESS_MAX_BYTES)] = {};
  if (address_to_bech32(&governor, w->bech32HRP, bech32_governor, sizeof(bech32_governor)) != 0) {
    printf("Failed converting governor address to bech32 format!\n");
    wallet_destroy(w);
    return -1;
  }

  printf("Sender address: %s\n", bech32_sender);
  printf("State controller address: %s\n", bech32_state_controller);
  printf("Governor address: %s\n", bech32_governor);
  printf("Amount to send: %" PRIu64 "\n", amount * Mi);

  // create alias output
  printf("Sending transaction message to the Tangle...\n");
  res_send_message_t msg_res = {};
  byte_t alias_id[ALIAS_ID_BYTES] = {0};
  byte_t alias_output_id[IOTA_OUTPUT_ID_BYTES] = {0};
  if (wallet_create_alias_output(w, 0, 0, amount * Mi, &state_controller, &governor, &msg_res, alias_id,
                                 alias_output_id) != 0) {
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

  // create a second transaction with an actual alias ID
  if (wallet_send_alias_state_transition(w, alias_id, &state_controller, &governor, alias_output_id,
                                         &state_controller_keypair, &msg_res) != 0) {
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
