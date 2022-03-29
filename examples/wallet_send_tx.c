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
#include "client/api/restful/get_balance.h"
#include "core/utils/byte_buffer.h"
#include "wallet/wallet.h"

#define Mi 1000000

#define NODE_HOST "api.lb-0.h.chrysalis-devnet.iota.cafe"
#define NODE_HOST_PORT 443
#define NODE_USE_TLS true

// replace this with your mnemonic string
static char const *const test_mnemonic = "your_testing_mnemonic_sentence";
char const *const bech32_receiver = "a_bech32_address";  // iota for mainnet, atoi for testnet
char const *const my_data = "sent from iota.c";
uint32_t const sender_addr_index = 0;  // address index of the wallet
uint64_t const amount = 1;             // sent out 1Mi

int main(int argc, char *argv[]) {
  int err = 0;
  char msg_id[IOTA_MESSAGE_ID_HEX_BYTES + 1] = {};
  // address with a version byte
  byte_t recv_addr[IOTA_ADDRESS_BYTES] = {};

  iota_wallet_t *wallet = wallet_create(test_mnemonic, "", 0);
  if (wallet) {
    wallet_set_endpoint(wallet, NODE_HOST, NODE_HOST_PORT, NODE_USE_TLS);
    if (wallet_update_bech32HRP(wallet) != 0) {
      wallet_destroy(wallet);
      printf("Connect Node failed\n");
      goto done;
    }

    // display balance before send
    uint64_t balance = 0;
    if ((err = wallet_balance_by_index(wallet, false, sender_addr_index, &balance))) {
      printf("get sender balance failed\n");
      goto done;
    }
    printf("balance: %" PRIu64 "\n", balance);

    // convert bech32 address to binary
    if ((err = address_from_bech32(wallet->bech32HRP, bech32_receiver, recv_addr))) {
      printf("convert receiver address failed\n");
      goto done;
    }
    // send out tokens
    // wallet_send take ed25519 address without the version field.
    if ((err = wallet_send(wallet, false, sender_addr_index, recv_addr + 1, amount * Mi, "iota.c\xF0\x9F\xA6\x8B",
                           (byte_t *)my_data, strlen(my_data), msg_id, sizeof(msg_id)))) {
      printf("send tx to %s failed\n", bech32_receiver);
      goto done;
    }
    printf("Message ID: %s\n", msg_id);

    // wait for the message to be confrimed
    printf("Check balance after 20s...\n");
    sleep(20);

    // check sender balance
    if ((err = wallet_balance_by_index(wallet, false, sender_addr_index, &balance))) {
      printf("get sender balance failed\n");
    } else {
      printf("balance after sent: %" PRIu64 "\n", balance);
    }

  } else {
    printf("Create wallet failed\n");
    return -1;
  }

done:
  wallet_destroy(wallet);
  return 0;
}
