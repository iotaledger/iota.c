// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdlib.h>
#include <string.h>

#include "core/address.h"
#include "core/utils/bech32.h"
#include "core/utils/byte_buffer.h"
#include "core/utils/macros.h"
#include "core/utils/slip10.h"

static int address_from_ed25519_pub(byte_t const pub_key[], address_t *addr) {
  addr->type = ADDRESS_TYPE_ED25519;
  return iota_blake2b_sum(pub_key, ED_PUBLIC_KEY_BYTES, addr->address, ED25519_PUBKEY_BYTES);
}

int address_keypair_from_path(byte_t seed[], size_t seed_len, char path[], ed25519_keypair_t *keypair) {
  // derive key from seed
  slip10_key_t key = {};
  int ret = slip10_key_from_path(seed, seed_len, path, ED25519_CURVE, &key);
  if (ret != 0) {
    printf("[%s:%d] derive key from path failed, err: %d\n", __func__, __LINE__, ret);
    return ret;
  }

  // ed25519 keypair from slip10 private key
  iota_crypto_keypair(key.key, keypair);
  return ret;
}

// get the length of corresponding address type
uint8_t address_len(address_t const *const addr) {
  switch (addr->type) {
    case ADDRESS_TYPE_ED25519:
      return ED25519_PUBKEY_BYTES;
    case ADDRESS_TYPE_ALIAS:
      return ALIAS_ID_BYTES;
    case ADDRESS_TYPE_NFT:
      return NFT_ID_BYTES;
    default:
      // unknown address type
      return 0;
  }
}

int ed25519_address_from_path(byte_t seed[], size_t seed_len, char path[], address_t *addr) {
  // ed25519 keypair from slip10 private key
  ed25519_keypair_t addr_keypair = {};

  if (address_keypair_from_path(seed, seed_len, path, &addr_keypair) != 0) {
    return -1;
  }
  return address_from_ed25519_pub(addr_keypair.pub, addr);
}

int alias_address_from_output(char const output_id[], address_t *addr) {
  addr->type = ADDRESS_TYPE_ALIAS;
  return iota_blake2b_sum((uint8_t const *const)output_id, strlen(output_id), addr->address, NFT_ID_BYTES);
}

int nft_address_from_output(char const output_id[], address_t *addr) {
  addr->type = ADDRESS_TYPE_NFT;
  return iota_blake2b_sum((uint8_t const *const)output_id, strlen(output_id), addr->address, NFT_ID_BYTES);
}

// get the length of
uint8_t address_serialized_len(address_t *addr) {
  // the serialized data is 1 byte + address bytes
  return 1 + address_len(addr);
}

size_t address_serialize(address_t *addr, byte_t bytes[], size_t len) {
  // validate parameters
  if (addr == NULL || bytes == NULL) {
    return 0;
  }

  // check buffer len
  if (len < address_serialized_len(addr)) {
    return 0;
  }

  bytes[0] = (uint8_t)addr->type;
  memcpy(bytes + 1, addr->address, address_len(addr));
  return sizeof(uint8_t) + address_len(addr);
}

address_t *address_deserialize(byte_t bytes[], size_t len) {
  // validate parameters
  if (bytes == NULL || len <= 1) {
    return NULL;
  }

  address_t *addr = malloc(sizeof(address_t));
  if (addr) {
    // address type
    addr->type = bytes[0];
    // check if binary length is satisfied
    if (len < address_serialized_len(addr)) {
      free_address(addr);
      return NULL;
    }

    // copy address
    switch (addr->type) {
      case ADDRESS_TYPE_ED25519:
        memcpy(addr->address, bytes + sizeof(uint8_t), ED25519_PUBKEY_BYTES);
        break;
      case ADDRESS_TYPE_ALIAS:
        memcpy(addr->address, bytes + sizeof(uint8_t), ALIAS_ID_BYTES);
        break;
      case ADDRESS_TYPE_NFT:
        memcpy(addr->address, bytes + sizeof(uint8_t), NFT_ID_BYTES);
        break;
      default:
        // unknown address type
        free_address(addr);
        printf("[%s:%d] unknown address type\n", __func__, __LINE__);
        return NULL;
    }
  }
  return addr;
}

// get the address object from the given hex string
int address_from_hex(char const hex[], address_t *addr) {
  // validate hex length
  if (hex == NULL || strlen(hex) < BIN_TO_HEX_STR_BYTES(ADDRESS_MIN_BYTES)) {
    return -1;
  }

  byte_t type = 0;
  if (hex_2_bin(hex, 2, &type, 1) != 0) {
    return -1;
  }
  addr->type = type;
  return hex_2_bin(hex + 2, BIN_TO_HEX_BYTES(address_len(addr)), addr->address, address_len(addr));
}

// get hex string from the given address object
int address_to_hex(address_t *addr, char hex_buf[], size_t buf_len) {
  // validate buffer
  if (hex_buf == NULL || buf_len <= BIN_TO_HEX_BYTES(address_serialized_len(addr))) {
    return -1;
  }
  if (bin_2_hex(addr->address, 1, hex_buf, 2) != 0) {
    return -1;
  }

  return bin_2_hex(addr->address + 1, address_len(addr), hex_buf + 2, buf_len - 2);
}

// get the address object from the given bech32 string
int address_from_bech32(char const hrp[], char const bech32[], address_t *addr) {
  if (addr == NULL || hrp == NULL || bech32 == NULL) {
    return -1;
  }

  char hrp_actual[84] = {};
  uint8_t data[64] = {};
  size_t data_len = 0;
  byte_t serialized_addr[ADDRESS_SERIALIZED_MAX_BYTES] = {};
  size_t serialized_len = 0;

  if (!bech32_decode(hrp_actual, data, &data_len, bech32)) {
    return -1;
  }

  if (data_len == 0 || data_len > 64) {
    return -1;
  }

  if (strncmp(hrp, hrp_actual, 84) != 0) {
    return -1;
  }

  if (!bech32_convert_bits(serialized_addr, &serialized_len, 8, data, data_len, 5, 0)) {
    return -1;
  }
  addr->type = (uint8_t)serialized_addr[0];
  memcpy(addr->address, serialized_addr + 1, address_len(addr));
  return 0;
}

// get the bech32 string from the given address object
int address_to_bech32(address_t *addr, char const hrp[], char bech32_buf[], size_t buf_len) {
  if (addr == NULL || hrp == NULL || bech32_buf == NULL || buf_len < 65) {
    return -1;
  }

  byte_t serialized_addr[33] = {};
  uint8_t data[64] = {};
  size_t data_len = 0;
  size_t ser_len = address_serialize(addr, serialized_addr, sizeof(serialized_addr));
  if (ser_len == 0) {
    return -1;
  }
  if (bech32_convert_bits(data, &data_len, 5, serialized_addr, ser_len, 8, 1) != 1) {
    return -1;
  }
  return !bech32_encode(bech32_buf, hrp, data, data_len);
}

bool address_equal(address_t *addr1, address_t *addr2) {
  if (addr1 == NULL || addr2 == NULL) {
    return false;
  }
  if (addr1->type == addr2->type) {
    int cmp = memcmp(addr1->address, addr2->address, address_len(addr1));
    return (cmp == 0);
  }
  return false;
}

address_t *address_clone(address_t const *const addr) {
  if (addr == NULL) {
    return NULL;
  }

  address_t *new_addr = malloc(sizeof(address_t));
  if (new_addr) {
    new_addr->type = addr->type;
    memset(new_addr->address, 0, ADDRESS_MAX_BYTES);
    memcpy(new_addr->address, addr->address, address_len(addr));
  }
  return new_addr;
}

void address_print(address_t const *const addr) {
  if (!addr) {
    return;
  }

  switch (addr->type) {
    case ADDRESS_TYPE_ED25519:
      printf("[ED25519] ");
      dump_hex_str(addr->address, ED25519_PUBKEY_BYTES);
      break;
    case ADDRESS_TYPE_ALIAS:
      printf("[Alias] ");
      dump_hex_str(addr->address, ALIAS_ID_BYTES);
      break;
    case ADDRESS_TYPE_NFT:
      printf("[NFT] ");
      dump_hex_str(addr->address, NFT_ID_BYTES);
      break;
    default:
      // unknown address type
      printf("[%s:%d] unknown address\n", __func__, __LINE__);
      break;
  }
}

void free_address(address_t *addr) {
  if (addr) {
    free(addr);
  }
}
