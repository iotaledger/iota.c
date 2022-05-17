// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/**
 * @brief A simple example of sending a transaction to the Tangle using wallet APIs.
 *
 */

#include <inttypes.h>
#include <stdio.h>

#include "wallet/output_basic.h"
#include "wallet/wallet.h"

#define Mi 1000000

#define NODE_HOST "localhost"
#define NODE_PORT 443
#define NODE_USE_TLS true
#define TEST_COIN_TYPE SLIP44_COIN_TYPE_SHIMMER

// replace this with your mnemonic string
static char const* const test_mnemonic =
    "acoustic trophy damage hint search taste love bicycle foster cradle brown govern endless depend situate athlete "
    "pudding blame question genius transfer van random vast";
static char const* const bech32_receiver =
    "atoi1qpswqe4v8z2cdtgc7sfj0hfneqh37lhmjgnth36mfndwcxkjrakcvx42lsn";  // receiver address in bech32 format
uint32_t const sender_addr_index = 0;                                    // address index of the wallet
uint64_t const amount = 1;  // transfer 1Mi from a sender to a receiver address

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

  // convert sender address to bech32 format
  char bech32_sender[BIN_TO_HEX_STR_BYTES(ADDRESS_MAX_BYTES)] = {};
  if (address_to_bech32(&sender, w->bech32HRP, bech32_sender, sizeof(bech32_sender)) != 0) {
    printf("Failed converting sender address to bech32 format!\n");
    wallet_destroy(w);
    return -1;
  }

  // convert bech32 address to binary
  if (address_from_bech32(w->bech32HRP, bech32_receiver, &receiver) != 0) {
    printf("Failed converting receiver address to binary format!\n");
    wallet_destroy(w);
    return -1;
  }

  printf("Sender address: %s\n", bech32_sender);
  printf("Receiver address: %s\n", bech32_receiver);
  printf("Amount to send: %" PRIu64 "\n", amount * Mi);

  // transfer tokens
  printf("Sending transaction message to the Tangle...\n");
  res_send_message_t msg_res = {};
  if (wallet_send_basic_output(w, 0, 0, &receiver, amount * Mi, &msg_res) != 0) {
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
