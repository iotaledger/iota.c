// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/**
 * @brief A simple example of sending a transaction to the Tangle use wallet APIs.
 *
 * Hierarchical Deterministic (HD) Wallets are defined by BIP32 and BIP44.
 * iota.c follows these specifications for generating wallets under the m/44/4218/0/0 path
 * and its underlying ed25199 addresses (bech32 format).
 *
 * The seed is the most important piece of information, and keeping it safe is essential
 * to identify oneself as owner of the specific amount of tokens stored in the specific wallet
 * in the context of a Distributed Ledger.
 *
 * Therefore, it is important that we educate users of the iota.c library about the dangers of
 * not handling seeds properly. Whenever the target hardware platform is supported by the Rust
 * compiler, the IOTA Foundation strongly suggests that all secret management is done via
 * Stronghold.
 *
 * If the project requires to rely purely on C source code, the use of a Hardware Security Module
 * (HSM) is strongly encouraged. Examples of HSMs are:
 * - STSAFE by STMicroelectronics
 * - ST33 by STMicroelectronics
 * - ATECC608B by Microchip
 *
 */

#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/utils/byte_buffer.h"
#include "wallet/wallet.h"

#define Mi 1000000

char const *const account_path = "m/44'/4218'/0'/0'";
char const *const node_url = "https://api.lb-0.testnet.chrysalis2.com/";
char const *const receiver = "atoi1q8dxnfl99slmsakun7pvqmcf5s5ctmzds3f38ehsygkuch4e5jymxuwr09p";
char const *const my_data = "sent from iota.c";

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
  byte_t seed[IOTA_SEED_BYTES] = {};
  // address with a version byte
  byte_t recv[IOTA_ADDRESS_BYTES] = {};
  iota_wallet_t *wallet = NULL;

  /*
   * Seed proves ownership of tokens!!! Therefore it must be **safely** retrieved
   * from some form of **secure storage**!!! We will generate a random seed for illustration.
   */
  randombytes_buf(seed, IOTA_ADDRESS_BYTES);

  // derive wallet from seed (BIP44)
  if ((wallet = wallet_create(seed, account_path)) == NULL) {
    printf("create wallet failed\n");
  }

  // erase seed variable from memory to reduce attack surface
  // however it remains inside wallet struct
  sodium_memzero(seed, IOTA_ADDRESS_BYTES);

  // set connected node
  wallet_set_endpoint(wallet, node_url, 0);

  dump_addresses(wallet, 0, 5);

  // convert receiver from bech32 to binary
  if ((err = address_from_bech32("atoi", receiver, recv))) {
    printf("convert receiver address failed\n");
    goto done;
  }

  // send none-valued transaction with indexation payload
  if ((err = wallet_send(wallet, 0, NULL, 0, "iota.c\xF0\x9F\x80\x84", (byte_t *)my_data, strlen(my_data)))) {
    printf("send indexation failed\n");
  }

  if ((err = wallet_send(wallet, 0, recv + 1, 0, "iota.c\xF0\x9F\x80\x84", (byte_t *)my_data, strlen(my_data)))) {
    printf("send indexation with address failed\n");
  }

  // send out 1Mi to recever address
  // wallet_send take ed25519 address without the version field.
  if ((err = wallet_send(wallet, 0, recv + 1, 1 * Mi, "iota.c\xF0\x9F\x80\x84", (byte_t *)my_data, strlen(my_data)))) {
    printf("send tx to %s failed\n", receiver);
  }

done:
  // remove last reference to seed from memory
  wallet_destroy(wallet);
  return 0;
}
