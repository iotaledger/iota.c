// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/**
 * @brief A simple example of sending a native tokens to the Tangle using wallet APIs.
 *
 */

#include <inttypes.h>
#include <stdio.h>

#include "wallet/output_basic.h"
#include "wallet/wallet.h"

#define NODE_HOST "localhost"
#define NODE_PORT 14265
#define NODE_USE_TLS false
#define TEST_COIN_TYPE SLIP44_COIN_TYPE_IOTA

// replace this with your mnemonic string
static char const* const test_mnemonic =
    "acoustic trophy damage hint search taste love bicycle foster cradle brown govern endless depend situate athlete "
    "pudding blame question genius transfer van random vast";
uint32_t const sender_addr_index = 3;     // address index of a sender
uint32_t const receiver_addr_index = 4;   // address index of a receiver
char const* const token_amount = "1000";  // transfer 1000 native tokens from a sender to a receiver address
char const* const token_id_str =
    "0860585c0a04a8a4a99c660ba1bf21794936997bed29ba8e054080037fb9017fd20100000000";  // token ID which will be sent

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
  char bech32_sender[BIN_TO_HEX_STR_BYTES(ADDRESS_MAX_BYTES)] = {};
  if (address_to_bech32(&sender, w->bech32HRP, bech32_sender, sizeof(bech32_sender)) != 0) {
    printf("Failed converting sender address to bech32 format!\n");
    wallet_destroy(w);
    return -1;
  }

  // convert receiver address to bech32 format
  char bech32_receiver[BIN_TO_HEX_STR_BYTES(ADDRESS_MAX_BYTES)] = {};
  if (address_to_bech32(&receiver, w->bech32HRP, bech32_receiver, sizeof(bech32_receiver)) != 0) {
    printf("Failed converting receiver address to bech32 format!\n");
    wallet_destroy(w);
    return -1;
  }

  // convert token id hex string to binary token id
  byte_t token_id[NATIVE_TOKEN_ID_BYTES] = {0};
  hex_2_bin(token_id_str, strlen(token_id_str), NULL, token_id, sizeof(token_id));

  printf("Sender address: %s\n", bech32_sender);
  printf("Receiver address: %s\n", bech32_receiver);
  printf("Native token ID: %s\n", token_id_str);
  printf("Amount to send: %s\n", token_amount);

  native_tokens_list_t* native_tokens = native_tokens_new();
  uint256_t* native_tokens_amount = uint256_from_str(token_amount);
  if (native_tokens_add(&native_tokens, token_id, native_tokens_amount) != 0) {
    printf("[%s:%d] can not add native token to a list\n", __func__, __LINE__);
    uint256_free(native_tokens_amount);
    wallet_destroy(w);
    return -1;
  }
  uint256_free(native_tokens_amount);

  // transfer tokens
  printf("Sending transaction message to the Tangle...\n");
  res_send_message_t msg_res = {};
  if (wallet_basic_output_send(w, false, sender_addr_index, 0, native_tokens, &receiver, &msg_res) != 0) {
    printf("Sending message to the Tangle failed!\n");
    native_tokens_free(native_tokens);
    wallet_destroy(w);
    return -1;
  }
  native_tokens_free(native_tokens);

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
