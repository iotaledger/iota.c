// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Reference: https://github.com/satoshilabs/slips/blob/master/slip-0010.md

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/utils/iota_str.h"
#include "core/utils/slip10.h"
#include "crypto/iota_crypto.h"

#ifndef htonl
#if ((__BYTE_ORDER__) == (__ORDER_LITTLE_ENDIAN__))
#define htonl(x) ((((x)&0xff) << 24) | (((x)&0xff00) << 8) | (((x)&0xff0000UL) >> 8) | (((x)&0xff000000UL) >> 24))
#else
#define htonl(x) (x)
#endif
#endif

// creates a new master private extended key for the curve from a seed.
static void master_key_generation(byte_t seed[], size_t seed_len, slip10_curve_t curve, slip10_key_t* key) {
  byte_t I[CRYPTO_SHA512_HASH_BYTES];
  char curve_key[CRYPTO_SHA512_KEY_BYTES] = {};
  // Calculate I = HMAC-SHA512(Key = Curve, Data = seed)
  if (curve == SECP256K1_CURVE) {
    strcpy(curve_key, "Bitcoin seed");
  } else if (curve == NIST_P256_CURVE) {
    strcpy(curve_key, "Nist256p1 seed");
  } else {
    strcpy(curve_key, "ed25519 seed");
  }

  iota_crypto_hmacsha512((uint8_t const*)curve_key, seed, seed_len, I);

  // Split I into two 32-byte sequences, I_L and I_R.
  memcpy(key->key, I, 32);
  memcpy(key->chain_code, I + 32, 32);
}

static void private_ckd(slip10_key_t* key, uint32_t index, byte_t I[]) {
  // I = HMAC-SHA512(Key = c_par, Data = 0x00 || ser_256(k_par) || ser_32(i))
  byte_t priv_data[37] = {};
  int priv_data_len = 0;
  if (index >= BIP32_HARDENED) {
    // data = 0x00 + key
    memcpy(priv_data + 1, key->key, 32);
    priv_data_len = 33;
  } else {
    // TODO: secp256k1 and NIST P-256 curves
  }
  // data += index in big-endian
  uint32_t be_index = htonl(index);
  memcpy(priv_data + priv_data_len, &be_index, sizeof(be_index));
  priv_data_len += sizeof(be_index);
  iota_crypto_hmacsha512(key->chain_code, priv_data, priv_data_len, I);
}

// derives a child extended private key from a given parent extended private key as outlined by SLIP-10.
static void child_key_derivation(uint32_t index, slip10_key_t* key) {
  // private parent key -> private child key
  byte_t I[64] = {};
  private_ckd(key, index, I);

  // Split I into two 32-byte sequences, I_L and I_R
  memcpy(key->chain_code, I + 32, 32);  // The returned chain code c_i is I_R.

  // I_L as ed25519's private key
  memcpy(key->key, I, 32);
  // TODO: secp256k1 and NIST P-256, compute the private key from I_L and k_par
}

// ParsePath parses s as a BIP-32 path, returning the result.
// The string s can be in the form where the apostrophe means hardened key ("m/44'/0'/0'/0/0")
// or where "H" means hardened key ("m/44H/0H/0H/0/0"). The "m/" prefix is mandatory.
int slip10_parse_path(char str[], bip32_path_t* path) {
  if (strlen(str) < 2) {
    return -1;
  }

  if (str[0] != 'm' && str[1] != '/') {
    // "m/" prefix is mandatory.
    return -1;
  }

  if (strstr(str, "//") != NULL || strstr(str, "''") != NULL || strstr(str, "'H") != NULL ||
      strstr(str, "H'") != NULL || strstr(str, "HH") != NULL || strstr(str, "h") != NULL) {
    // invalid path format
    return -1;
  }

  int ret = 0;
  iota_str_t* path_buf = iota_str_new(str + 2);
  char* token = strtok(path_buf->buf, "/");
  path->len = 0;
  while (token != NULL) {
    char* ptr = NULL;
    // check token format
    if (strncmp(token, "\'", 1) == 0 || strncmp(token, "H", 1) == 0) {
      // invalid format
      ret = -1;
      goto end;
    }

    // get value
    unsigned long value = strtoul(token, &ptr, 10);
    if (value >= BIP32_HARDENED) {
      // out of range
      ret = -2;
      goto end;
    }

    // hardened
    if (strncmp(ptr, "\'", 1) == 0 || strncmp(ptr, "H", 1) == 0) {
      value |= BIP32_HARDENED;
    }
    path->path[path->len] = value;

    // gets next token
    token = strtok(NULL, "/");
    path->len += 1;

    if (path->len >= MAX_PIB32_PATH) {
      // path too long
      ret = -3;
      goto end;
    }
  }
end:
  iota_str_destroy(path_buf);
  return ret;
}

int slip10_key_from_path(byte_t seed[], size_t seed_len, char path[], slip10_curve_t curve, slip10_key_t* key) {
  if (curve == SECP256K1_CURVE || curve == NIST_P256_CURVE) {
    // TODO: support secp256k1 and NIST P-256 curves
    return -1;
  }

  bip32_path_t bip32_path = {};
  if (slip10_parse_path(path, &bip32_path) != 0) {
    // invalid path
    return -2;
  }

  master_key_generation(seed, seed_len, curve, key);

  for (int i = 0; i < bip32_path.len; i++) {
    if (curve == ED25519_CURVE && bip32_path.path[i] < BIP32_HARDENED) {
      // ed25519 only supports hardened indices
      return -3;
    }
    child_key_derivation(bip32_path.path[i], key);
  }

  return 0;
}

int slip10_public_key(slip10_curve_t curve, slip10_key_t* key, byte_t pub_key[]) {
  if (curve == SECP256K1_CURVE || curve == NIST_P256_CURVE) {
    // TODO: support secp256k1 and NIST P-256 curves
    return -1;
  }
  // public key
  iota_keypair_t keypair = {};
  iota_crypto_keypair(key->key, &keypair);
  // match the required public key size, SLIP10_PUBLIC_KEY_BYTES
  pub_key[0] = 0x00;
  memcpy(pub_key + 1, keypair.pub, ED_PUBLIC_KEY_BYTES);
  return 0;
}
