// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/**
 * @brief A simple example of sending a transaction to the Tangle use wallet APIs.
 *
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "client/api/message.h"
#include "client/api/v1/get_balance.h"
#include "core/utils/byte_buffer.h"
#include "wallet/wallet.h"

#define Mi 1000000

#define NODE_HOST "api.lb-0.testnet.chrysalis2.com"
#define NODE_HOST_PORT 443
#define NODE_USE_TLS true

char const *const my_seed = "seed_with_64_char";
char const *const account_path = "m/44'/4218'/0'/0'";
char const *const receiver = "a_bech32_address";  // iota for mainnet, atoi for testnet
char const *const my_data = "sent from iota.c";
uint32_t const sender_addr_index = 2;  // address index of the wallet
uint64_t const amount = 1;             // sent out 1Mi

void dump_addresses(iota_wallet_t *w, uint32_t start, uint32_t end) {
  byte_t addr_wit_version[IOTA_ADDRESS_BYTES] = {};
  char tmp_bech32_addr[100] = {};

  for (uint32_t i = start; i <= end; i++) {
    addr_wit_version[0] = ADDRESS_VER_ED25519;
    wallet_address_by_index(w, i, addr_wit_version + 1);
    address_2_bech32(addr_wit_version, "atoi", tmp_bech32_addr);
    printf("Addr[%" PRIu32 "]\n", i);
    // print ed25519 address without version filed.
    printf("\t");
    dump_hex_str(addr_wit_version + 1, ED25519_ADDRESS_BYTES);
    // print out
    printf("\t%s\n", tmp_bech32_addr);
  }
}

int main(int argc, char *argv[]) {
  int err = 0;
  char msg_id[IOTA_MESSAGE_ID_HEX_BYTES + 1] = {};
  byte_t seed[IOTA_SEED_BYTES] = {};
  // address with a version byte
  byte_t recv[IOTA_ADDRESS_BYTES] = {};
  iota_wallet_t *wallet = NULL;

  if (strlen(my_seed) != 64) {
    printf("invalid seed string, it should be a 64-character-string..\n");
    return -1;
  }

  // convert seed from hex string to binary
  if ((err = hex_2_bin(my_seed, strlen(my_seed), seed, sizeof(seed)))) {
    printf("convert seed failed\n");
    goto done;
  }

  if ((wallet = wallet_create(seed, account_path)) == NULL) {
    printf("create wallet failed\n");
    goto done;
  }

  // set connected node
  wallet_set_endpoint(wallet, NODE_HOST, NODE_HOST_PORT, NODE_USE_TLS);
  wallet_update_bech32HRP(wallet);

  dump_addresses(wallet, 0, 5);

  // check balance at address 0
  uint64_t value = 0;
  if ((err = wallet_balance_by_index(wallet, sender_addr_index, &value))) {
    printf("wallet get balance failed\n");
    goto done;
  }
  printf("[%d]balance: %" PRIu64 "\n", sender_addr_index, value);

  // send out 1Mi to receiver address
  // convert bech32 address to binary
  if ((err = address_from_bech32(wallet->bech32HRP, receiver, recv))) {
    printf("convert receiver address failed\n");
    goto done;
  }

  // wallet_send take ed25519 address without the version field.
  if ((err = wallet_send(wallet, sender_addr_index, recv + 1, amount * Mi, "iota.c\xF0\x9F\xA6\x8B", (byte_t *)my_data,
                         strlen(my_data), msg_id, sizeof(msg_id)))) {
    printf("send tx to %s failed\n", receiver);
    goto done;
  }
  printf("Message ID: %s\n", msg_id);

  printf("Check balance after 20s...\n");
  sleep(20);

  // sender balance
  uint64_t sender_tokens = 0;
  if ((err = wallet_balance_by_index(wallet, sender_addr_index, &sender_tokens))) {
    printf("get sender balance failed\n");
  }

  // receiver balance
  char recv_addr_hex[API_ADDR_HEX_STR_LEN] = {};
  // convert bin address to hex string for node API
  bin_2_hex(recv + 1, ED25519_ADDRESS_BYTES, recv_addr_hex, sizeof(recv_addr_hex));
  res_balance_t *res = res_balance_new();
  if (res) {
    if ((err = get_balance(&wallet->endpoint, recv_addr_hex, res))) {
      printf("get receiver balance failed\n");
    } else {
      printf("sender balance = %" PRIu64 " receiver balance = %" PRIu64 "\n", sender_tokens,
             res->u.output_balance->balance);
    }
    res_balance_free(res);
  }

done:
  wallet_destroy(wallet);
  return 0;
}
