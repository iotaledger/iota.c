// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

#include "core/address.h"
#include "core/utils/bech32.h"
#include "core/utils/slip10.h"
#include "crypto/iota_crypto.h"

int address_from_ed25519_pub(byte_t const pub_key[], byte_t addr[]) {
  return iota_blake2b_sum(pub_key, ED_PUBLIC_KEY_BYTES, addr, ED25519_ADDRESS_BYTES);
}

int address_keypair_from_path(byte_t seed[], char path[], iota_keypair_t* keypair) {
  // derive key from seed
  slip10_key_t key = {};
  int ret = 0;
  if ((ret = slip10_key_from_path(seed, IOTA_SEED_BYTES, path, ED25519_CURVE, &key)) != 0) {
    printf("[%s:%d] derive key from path failed, err: %d\n", __func__, __LINE__, ret);
    return ret;
  }

  // ed25519 keypair from slip10 private key
  iota_crypto_keypair(key.key, keypair);
  return ret;
}

int address_from_path(byte_t seed[], char path[], byte_t out_addr[]) {
  // ed25519 keypair from slip10 private key
  iota_keypair_t addr_keypair = {};
  int ret = 0;
  if ((ret = address_keypair_from_path(seed, path, &addr_keypair)) == 0) {
    return address_from_ed25519_pub(addr_keypair.pub, out_addr);
  }
  return ret;
}

int address_from_bech32(char const* hrp, char const* bech32_str, byte_t out_addr[]) {
  size_t len = 0;
  int ret = iota_addr_bech32_decode(out_addr, &len, hrp, bech32_str);
  // out_addr is an address with a verion byte which is 33 bytes
  if (len != IOTA_ADDRESS_BYTES || ret != 1) {
    return -1;
  }
  return 0;
}

int address_2_bech32(byte_t const addr[], char const* hrp, char* bech32_addr) {
  // out_addr is an address with a verion byte which is 33 bytes
  return !iota_addr_bech32_encode(bech32_addr, hrp, addr, IOTA_ADDRESS_BYTES);
}
