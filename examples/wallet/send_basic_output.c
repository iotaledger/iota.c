// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/**
 * @brief A simple example of sending a transaction to the Tangle using wallet APIs.
 *
 */

#include <inttypes.h>
#include <stdio.h>

#include "core/utils/bech32.h"
#include "wallet/output_basic.h"
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
uint32_t const sender_addr_index = 0;    // address index of a sender
uint32_t const receiver_addr_index = 1;  // address index of a receiver
uint64_t const amount = 1;               // transfer 1Mi from a sender to a receiver address

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

  address_t sender, receiver;
  if (wallet_ed25519_address_from_index(w, false, sender_addr_index, &sender) != 0) {
    printf("Failed to generate a sender address from an index!\n");
    wallet_destroy(w);
    return -1;
  }
  if (wallet_ed25519_address_from_index(w, false, receiver_addr_index, &receiver) != 0) {
    printf("Failed to generate a receiver address from an index!\n");
    wallet_destroy(w);
    return -1;
  }

  // convert sender address to bech32 format
  char bech32_sender[BECH32_MAX_STRING_LEN + 1] = {};
  if (address_to_bech32(&sender, w->bech32HRP, bech32_sender, sizeof(bech32_sender)) != 0) {
    printf("Failed converting sender address to bech32 format!\n");
    wallet_destroy(w);
    return -1;
  }

  // convert receiver address to bech32 format
  char bech32_receiver[BECH32_MAX_STRING_LEN + 1] = {};
  if (address_to_bech32(&receiver, w->bech32HRP, bech32_receiver, sizeof(bech32_receiver)) != 0) {
    printf("Failed converting receiver address to bech32 format!\n");
    wallet_destroy(w);
    return -1;
  }

  printf("Sender address: %s\n", bech32_sender);
  printf("Receiver address: %s\n", bech32_receiver);
  printf("Amount to send: %" PRIu64 "\n", amount * Mi);

  // transfer tokens
  printf("\nSending transaction block to the Tangle...\n");
  res_send_block_t blk_res = {};
  if (wallet_basic_output_send(w, false, sender_addr_index, amount * Mi, NULL, &receiver, &blk_res) != 0) {
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

  wallet_destroy(w);

  return 0;
}
