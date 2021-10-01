// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <string.h>

#include "crypto/iota_crypto.h"
#include "utf8proc.h"
#include "wallet/bip39.h"

#ifndef BIP39_ENGLISH_ONLY
#include "wallet/wordlists/chinese_simplified.h"
#include "wallet/wordlists/chinese_traditional.h"
#include "wallet/wordlists/czech.h"
#include "wallet/wordlists/english.h"
#include "wallet/wordlists/french.h"
#include "wallet/wordlists/italian.h"
// #include "wallet/wordlists/japanese.h" // TODO, or not support
#include "wallet/wordlists/korean.h"
#include "wallet/wordlists/portuguese.h"
#include "wallet/wordlists/spanish.h"
#else
#include "wallet/wordlists/english.h"
#endif

// max length of ENT+CS in byte, 33 bytes
#define BIP39_MAX_ENT_CS_BYTES (264 / 8)

// mnemonic sentence count in language files
#define BIP39_WORDLIST_COUNT 2048

// BIP39 split entropy into groups of 11 bits.
#define BIP39_GROUP_BITS 11
// maximum words of mnemonic sentence(MS)
#define BIP39_MAX_MS 24

// japaneses uses the "　"(\u3000) seperator
// https://github.com/bip32JP/bip32JP.github.io/blob/d2475a57735bdc06da615481a9d2232e090e69f7/js/bip39.js#L45-L49
#define BIP39_MS_SEPERATOR_JA L"　"
#define BIP39_MS_SEPERATOR " "

/**
 * @brief Store index of mnemonic sentence
 *
 */
typedef struct {
  uint16_t index[BIP39_MAX_MS];  ///< index of the word
  uint8_t len;                   ///< the number of words in this MS.
} ms_index_t;

/**
 * @brief Get index value from a word
 *
 * @param[in] entropy the entropy data buffer
 * @param[in] n the n-th word
 * @return size_t the index value
 */
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

/**
 * @brief build the index table from entropy
 *
 * @param[in] entropy the input entropy
 * @param[in] entropy_len the bytes of entropy
 * @param[out] ms_index index table for a mnemonic sentence
 * @return int 0 on success
 */
static int index_from_entropy(byte_t const entropy[], ms_entropy_t entropy_len, ms_index_t *ms_index) {
  byte_t checksum_buf[CRYPTO_SHA256_HASH_BYTES] = {};
  byte_t ENT_buf[BIP39_MAX_ENT_CS_BYTES] = {};
  uint8_t checksum = 0;
  uint8_t checksum_mask = 0x0;
  uint8_t ms_len = 0;

  if (entropy == NULL || entropy_len == 0) {
    printf("[%s:%d] invalid entropy\n", __func__, __LINE__);
    return -1;
  }

  switch (entropy_len) {
    case MS_ENTROPY_128:
      checksum_mask = 0xF0;  // 4 bits
      ms_len = 12;
      break;
    case MS_ENTROPY_160:
      checksum_mask = 0xF8;  // 5 bits
      ms_len = 15;
      break;
    case MS_ENTROPY_192:
      checksum_mask = 0xFC;  // 6 bits
      ms_len = 18;
      break;
    case MS_ENTROPY_224:
      checksum_mask = 0xFE;  // 7 bits
      ms_len = 21;
      break;
    case MS_ENTROPY_256:
      checksum_mask = 0xFF;  // 8 bits
      ms_len = 24;
      break;
    default:
      break;
  }

  if (checksum_mask == 0x0 || ms_len == 0) {
    printf("[%s:%d] invalid entropy length\n", __func__, __LINE__);
    return -1;
  }

  // get checksum from entropy
  if (iota_crypto_sha256(entropy, entropy_len, checksum_buf) != 0) {
    printf("[%s:%d] checksum failed\n", __func__, __LINE__);
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

/**
 * @brief convert index to entropy value
 *
 * @param[in] n the n-th word in ms
 * @param[in] value the index value of word
 * @param[out] entropy an entropy buffer should bigger than BIP39_MAX_ENT_CS_BYTES
 */
static void index_to_entropy(size_t n, size_t value, byte_t entropy[]) {
  size_t start = n * BIP39_GROUP_BITS;  // start index of this group
  for (size_t i = 0; i < BIP39_GROUP_BITS; i++, start++) {
    if (value & (1u << (BIP39_GROUP_BITS - i - 1u))) {
      // the mask of the bit we need
      byte_t mask = (1u << (7u - start % 8));
      // store to entropy
      entropy[start / 8] |= mask;
    }
  }
}

/**
 * @brief Get the language table
 *
 * @param[in] lan language to find
 * @return word_t* a pointer of the language table
 */
static word_t *get_lan_table(ms_lan_t lan) {
  switch (lan) {
    case MS_LAN_EN:
      return en_word;
#ifndef BIP39_ENGLISH_ONLY
    case MS_LAN_CS:
      return cs_word;
    case MS_LAN_ES:
      return es_word;
    case MS_LAN_FR:
      return fr_word;
    case MS_LAN_IT:
      return it_word;
    // case MS_LAN_JA:
    //   return ja_word;
    case MS_LAN_KO:
      return ko_word;
    case MS_LAN_PT:
      return pt_word;
    case MS_LAN_ZH_HANT:
      return zh_hant_word;
    case MS_LAN_ZH_HANS:
      return zh_hans_word;
#endif
    default:
      return en_word;
  }
}

/**
 * @brief Calculate entropy bytes from MS length
 *
 * @param[in] len the length of a mnemonic sentence
 * @return size_t the bytes of entropy
 */
static size_t ENT_from_MS(uint8_t len) {
  switch (len) {
    case 12:
      return MS_ENTROPY_128;
    case 15:
      return MS_ENTROPY_160;
    case 18:
      return MS_ENTROPY_192;
    case 21:
      return MS_ENTROPY_224;
    case 24:
      return MS_ENTROPY_256;
    default:
      return 0;
  }
}

size_t mnemonic_decode(char const ms_strs[], ms_lan_t lan, byte_t entropy[], size_t ent_len) {
  if (ms_strs == NULL || entropy == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  // copy string to another buffer
  char *ms_p = malloc((strlen(ms_strs) + 1) * sizeof(char));
  if (ms_p == NULL) {
    printf("[%s:%d] allocate buffer failed\n", __func__, __LINE__);
    return 0;
  }
  strcpy(ms_p, ms_strs);

  // get corresponding wordlist
  word_t *word_table = get_lan_table(lan);
  // index of ms
  ms_index_t ms = {};

  // cleanup, bits are zero for writing
  memset(entropy, 0, ent_len);

  char *token = strtok(ms_p, BIP39_MS_SEPERATOR);
  int w_count = 0;
  while (token != NULL) {
    for (size_t i = 0; i < BIP39_WORDLIST_COUNT; i++) {
      if (strcmp(token, word_table[i].p) == 0) {
        // index found
        ms.index[w_count] = i;
        index_to_entropy(w_count, ms.index[w_count], entropy);
        break;
      }
    }
    w_count++;
    token = strtok(NULL, BIP39_MS_SEPERATOR);
  }
  // words in the ms
  ms.len = w_count;
  free(ms_p);
  return ENT_from_MS(ms.len);
}

int mnemonic_encode(byte_t const entropy[], ms_entropy_t ent_len, ms_lan_t lan, char ms_out[], size_t ms_len) {
  ms_index_t ms = {};

  if (entropy == NULL || ms_out == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  if (index_from_entropy(entropy, ent_len, &ms) == 0) {
    // default to english
    word_t *lan_p = get_lan_table(lan);

    // get string from the wordlist
    size_t offset = 0;
    for (size_t i = 0; i < ms.len; i++) {
      int n;
      if (i < ms.len - 1) {
        n = snprintf(ms_out + offset, ms_len - offset, "%s%s", lan_p[ms.index[i]].p, BIP39_MS_SEPERATOR);
      } else {
        n = snprintf(ms_out + offset, ms_len - offset, "%s", lan_p[ms.index[i]].p);
      }

      offset += n;
      if (offset >= ms_len) {
        printf("[%s:%d] output buffer is too small\n", __func__, __LINE__);
        return -1;
      }
    }
    return 0;
  }
  return -1;
}

int mnemonic_generator(ms_entropy_t ent_len, ms_lan_t lang, char ms[], size_t ms_len) {
  byte_t ent_tmp[MS_ENTROPY_256] = {};
  iota_crypto_randombytes(ent_tmp, MS_ENTROPY_256);
  return mnemonic_encode(ent_tmp, ent_len, lang, ms, ms_len);
}

int mnemonic_to_seed(char const ms[], char const pwd[], byte_t seed[], size_t seed_len) {
  char const *const phrase = "mnemonic";
  size_t phrase_len = strlen(phrase);

  if (ms == NULL || pwd == NULL || seed == NULL) {
    return -1;
  }

  if (seed_len < BIP39_SEED_BYTES) {
    return -2;
  }

  utf8proc_uint8_t *normalize_ms = utf8proc_NFKD((utf8proc_uint8_t *)ms);
  if (normalize_ms == NULL) {
    return -3;
  }

  utf8proc_uint8_t *normalize_pwd = utf8proc_NFKD((utf8proc_uint8_t *)pwd);
  if (normalize_pwd == NULL) {
    free(normalize_ms);
    return -4;
  }
  size_t pwd_len = strlen((char const *)normalize_pwd);

  byte_t *phrase_tmp = malloc(phrase_len + pwd_len + 1 * sizeof(byte_t));
  if (phrase_tmp == NULL) {
    free(normalize_ms);
    free(normalize_pwd);
    return -5;
  }

  memcpy(phrase_tmp, phrase, phrase_len);
  memcpy(phrase_tmp + phrase_len, normalize_pwd, pwd_len);
  phrase_tmp[phrase_len + pwd_len] = '\0';

  utf8proc_uint8_t *normalize_phrase = utf8proc_NFKD(phrase_tmp);
  if (normalize_phrase == NULL) {
    free(normalize_ms);
    free(normalize_pwd);
    free(phrase_tmp);
    return -6;
  }

  iota_crypto_pbkdf2_hmac_sha512((char const *)normalize_ms, strlen((char const *)normalize_ms),
                                 (char const *)normalize_phrase, strlen((char const *)normalize_phrase), 2048, seed,
                                 seed_len);
  free(normalize_ms);
  free(normalize_pwd);
  free(phrase_tmp);
  free(normalize_phrase);

  return 0;
}

int mnemonic_convertor(char const from[], ms_lan_t lan_from, char to[], size_t to_len, ms_lan_t lan_to) {
#ifndef BIP39_ENGLISH_ONLY
  printf("[%s:%d] not supported\n", __func__, __LINE__);
  return -1;
#else
  byte_t ent[BIP39_MAX_ENT_CS_BYTES] = {};
  size_t ent_len = mnemonic_decode(from, lan_from, ent, sizeof(ent));
  if (ent_len == 0) {
    printf("[%s:%d] mnemonic decode error\n", __func__, __LINE__);
    return -1;
  }
  return mnemonic_encode(ent, ent_len, lan_to, to, to_len);
#endif
}

bool mnemonic_validation(char const ms[], ms_lan_t language) {
  byte_t ent[BIP39_MAX_ENT_CS_BYTES] = {};
  size_t ent_len = mnemonic_decode(ms, language, ent, sizeof(ent));
  return ent_len ? true : false;
}
