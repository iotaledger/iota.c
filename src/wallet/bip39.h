// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __WALLET_BIP39_H__
#define __WALLET_BIP39_H__

#include <stdbool.h>
#include <stdint.h>

#include "core/types.h"

#define BIP39_SEED_BYTES 64

/**
 * @brief Mnemonic supported languages with ISO 639-1 suffixes
 *
 */
typedef enum {
  MS_LAN_EN,  ///< English
#ifndef BIP39_ENGLISH_ONLY
  MS_LAN_KO,       ///< Korean
  MS_LAN_ES,       ///< Spanish
  MS_LAN_ZH_HANT,  ///< Chinese Traditional
  MS_LAN_ZH_HANS,  ///< Chinese Simplified
  MS_LAN_FR,       ///< French
  MS_LAN_IT,       ///< Italian
  MS_LAN_CS,       ///< Czech
  MS_LAN_PT,       ///< Portuguese
// MS_LAN_JA, ///< Japanese, TODO or not support
#endif
} ms_lan_t;

/**
 * @brief Init entropy of mnemonic sentense
 *
 * With more entropy security is improved but the sentence length increases.
 *
 */
typedef enum {
  MS_ENTROPY_128 = 16,  ///< 12 mnemonic words
  MS_ENTROPY_160 = 20,  ///< 15 mnemonic words
  MS_ENTROPY_192 = 24,  ///< 18 mnemonic words
  MS_ENTROPY_224 = 28,  ///< 21 mnemonic words
  MS_ENTROPY_256 = 32   ///< 24 mnemonic words
} ms_entropy_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Drive seed from a given mnemonic sentence
 *
 * @param[in] ms A mnemonic sentence
 * @param[in] pwd A password string
 * @param[out] seed A buffer holds output seed
 * @param[in] seed_len the length of seed buffer
 * @return int
 */
int mnemonic_to_seed(char const ms[], char const pwd[], byte_t seed[], size_t seed_len);

/**
 * @brief Generate a randome word list from given entropy length
 *
 * @param[in] ent_len the init entropy length
 * @param[in] lang the language of mnemonic
 * @param[out] ms a buffer holds the mnemonic string
 * @param[in] ms_len the length of mnemonic buffer
 * @return int 0 on success
 */
int mnemonic_generator(ms_entropy_t ent_len, ms_lan_t lang, char ms[], size_t ms_len);

/**
 * @brief decode mnemonic sentence to the entropy.
 *
 * @param[in] ms_strs A string of mnemonic sentence
 * @param[in] lan The language of the mnemonic sentence
 * @param[out] entropy the output buffer, should bigger than 33 bytes(ENT+CS)
 * @param[in] ent_len the size of the entropy buffer
 * @return size_t the bytes written to output buffer, 0 on failed.
 */
size_t mnemonic_decode(char const ms_strs[], ms_lan_t lan, byte_t entropy[], size_t ent_len);

/**
 * @brief encode mnemonic sentence from a given entropy.
 *
 * @param[in] entropy the input entroty
 * @param[in] ent_len the length of entroty, should be one of 16, 20, 24, 28, 32.
 * @param[in] lan The expected language of mnemonic sentence
 * @param[out] ms_out The output string of mnemonic sentence
 * @param[in] ms_len the output buffer length
 * @return int 0 on success
 */
int mnemonic_encode(byte_t const entropy[], ms_entropy_t ent_len, ms_lan_t lan, char ms_out[], size_t ms_len);

/**
 * @brief Convert mnemonic to another language
 *
 * @param[in] from A source mnemonic sentence
 * @param[in] lan_from The language of source mnemonic
 * @param[in] lan_to The language of target mnemonic
 * @param[out] to A buffer for target mnemonic
 * @param[out] to_len The length of target buffer
 * @return int
 */
int mnemonic_convertor(char const from[], ms_lan_t lan_from, char to[], size_t to_len, ms_lan_t lan_to);

/**
 * @brief Check if mnemonic sentence is valid
 *
 * @param[in] ms A string of mnemonic sentence
 * @param[in] language The language of the given mnemonic
 * @return true valid sentence
 * @return false invalid sentence
 */
bool mnemonic_validation(char const ms[], ms_lan_t language);

#ifdef __cplusplus
}
#endif

#endif  // __WALLET_BIP39_H__
