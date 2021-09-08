// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifdef EN_WALLET_BIP39

#include <string.h>

#include "crypto/iota_crypto.h"
#include "wallet/bip39.h"

#include "wallet/wordlists/chinese_simplified.h"
#include "wallet/wordlists/chinese_traditional.h"
#include "wallet/wordlists/czech.h"
#include "wallet/wordlists/english.h"
#include "wallet/wordlists/french.h"
#include "wallet/wordlists/italian.h"
#include "wallet/wordlists/japanese.h"
#include "wallet/wordlists/korean.h"
#include "wallet/wordlists/portuguese.h"
#include "wallet/wordlists/spanish.h"

// valid init entropy lengths in byte, ENT
#define BIP39_ENT_128_BYTES 16
#define BIP39_ENT_160_BYTES 20
#define BIP39_ENT_192_BYTES 24
#define BIP39_ENT_224_BYTES 28
#define BIP39_ENT_256_BYTES 32

// max length of ENT+CS in byte
#define BIP39_MAX_ENT_CS_BYTES (264 / 8)

// mnemonic sentence count in language files
#define BIP39_WORDLIST_COUNT 2048

// BIP39 split entropy into groups of 11 bits.
#define BIP39_GROUP_BITS 11

// index of mnemonic sentence
typedef struct {
  uint16_t index[24];
  uint8_t len;
} ms_index_t;

// get word index from entropy group
static size_t word_index(byte_t const entropy[], size_t n) {
  size_t start = n * BIP39_GROUP_BITS;    // start index of this group
  size_t end = start + BIP39_GROUP_BITS;  // end index of this group
  size_t index = 0;
  while (start < end) {
    // the byte of current position
    byte_t b = entropy[start / 8];
    // the mask of the bit we need
    byte_t mask = (1u << (7u - start % 8));
    // for adding a bit
    index = (index << 1u);
    // append 1 if the bit is set
    index |= ((b & mask) == mask) ? 1 : 0;

    start++;
  }
  return index;
}

static int index_from_entropy(byte_t const entropy[], uint32_t entropy_len, ms_index_t *ms_index) {
  byte_t checksum_buf[CRYPTO_SHA256_HASH_BYTES] = {};
  byte_t ENT_buf[BIP39_MAX_ENT_CS_BYTES] = {};
  uint8_t checksum = 0;
  uint8_t checksum_mask = 0x0;
  uint8_t ms_len = 0;

  if (entropy == NULL || entropy_len == 0) {
    printf("invalid entropy\n");
    return -1;
  }

  switch (entropy_len) {
    case BIP39_ENT_128_BYTES:
      checksum_mask = 0xF0;  // 4 bits
      ms_len = 12;
      break;
    case BIP39_ENT_160_BYTES:
      checksum_mask = 0xF8;  // 5 bits
      ms_len = 15;
      break;
    case BIP39_ENT_192_BYTES:
      checksum_mask = 0xFC;  // 6 bits
      ms_len = 18;
      break;
    case BIP39_ENT_224_BYTES:
      checksum_mask = 0xFE;  // 7 bits
      ms_len = 21;
      break;
    case BIP39_ENT_256_BYTES:
      checksum_mask = 0xFF;  // 8 bits
      ms_len = 24;
      break;
    default:
      break;
  }

  if (checksum_mask == 0x0 || ms_len == 0) {
    printf("invalid entropy length\n");
    return -1;
  }

  // get checksum from entropy
  if (iota_crypto_sha256(entropy, entropy_len, checksum_buf) != 0) {
    printf("get checksum failed\n");
    return -1;
  }

  uint8_t ent_cs_len = entropy_len + 1;
  checksum = checksum_buf[0] & checksum_mask;
  // final entropy with checksum
  memcpy(ENT_buf, entropy, entropy_len);
  // addpend checksum to the end of initial entropy
  memcpy(ENT_buf + entropy_len, &checksum, 1);

  // dump_hex_str(ENT_buf, ent_cs_len);

  ms_index->len = ms_len;
  for (size_t i = 0; i < ms_len; i++) {
    ms_index->index[i] = word_index(ENT_buf, i);
  }
  return 0;
}

static void index_to_entropy(ms_index_t *ms, byte_t entropy[], size_t ent_len) {
  // validate length
}

int mnemonic_from_seed(byte_t const seed[], uint32_t seed_len, ms_lan_t lan, char buf_out[], size_t buf_len) {
  ms_index_t ms = {};

  if (seed == NULL || buf_out == NULL) {
    printf("invalid parameters");
    return -1;
  }

  if (index_from_entropy(seed, seed_len, &ms) == 0) {
    // default to english
    word_t *lan_p = en_word;
    // get lang
    switch (lan) {
      case MS_LAN_EN:
        lan_p = en_word;
        break;
      case MS_LAN_CS:
        lan_p = cs_word;
        break;
      case MS_LAN_ES:
        lan_p = es_word;
        break;
      case MS_LAN_FR:
        lan_p = fr_word;
        break;
      case MS_LAN_IT:
        lan_p = it_word;
        break;
      case MS_LAN_JA:
        lan_p = ja_word;
        break;
      case MS_LAN_KO:
        lan_p = ko_word;
        break;
      case MS_LAN_PT:
        lan_p = pt_word;
        break;
      case MS_LAN_ZH_HANT:
        lan_p = zh_hant_word;
        break;
      case MS_LAN_ZH_HANS:
        lan_p = zh_hans_word;
        break;
      default:
        break;
    }

    // dump string
    int offset = 0;
    for (size_t i = 0; i < ms.len; i++) {
      // printf("%u, ", ms.index[i]);
      int n;
      if (i < ms.len - 1) {
        if (lan == MS_LAN_JA) {
          // japaneses uses the "　"(\u3000) seperator
          // https://github.com/bip32JP/bip32JP.github.io/blob/d2475a57735bdc06da615481a9d2232e090e69f7/js/bip39.js#L45-L49
          n = snprintf(buf_out + offset, buf_len - offset, "%s　", lan_p[ms.index[i]].p);
        } else {
          n = snprintf(buf_out + offset, buf_len - offset, "%s ", lan_p[ms.index[i]].p);
        }
      } else {
        n = snprintf(buf_out + offset, buf_len - offset, "%s", lan_p[ms.index[i]].p);
      }

      offset += n;
      if (offset >= buf_len) {
        printf("output buffer is too small\n");
        return -1;
      }
    }
    return 0;
  }
  return -1;
}
#endif
