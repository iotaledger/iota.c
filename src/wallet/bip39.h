// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __WALLET_BIP39_H__
#define __WALLET_BIP39_H__

#ifdef EN_WALLET_BIP39

#include <stdint.h>

#include "core/types.h"

/**
 * @brief Mnemonic supported languages with ISO 639-1 suffixes
 *
 */
typedef enum {
  MS_LAN_EN,       ///< English
  MS_LAN_KO,       ///< Korean
  MS_LAN_ES,       ///< Spanish
  MS_LAN_ZH_HANT,  ///< Chinese Traditional
  MS_LAN_ZH_HANS,  ///< Chinese Simplified
  MS_LAN_FR,       ///< French
  MS_LAN_IT,       ///< Italian
  MS_LAN_CS,       ///< Czech
  MS_LAN_PT,       ///< Portuguese
  // MS_LAN_JA, ///< Japanese, TODO or not support
} ms_lan_t;

#ifdef __cplusplus
extern "C" {
#endif

// void mnemonic_to_seed(); // TODO

/**
 * @brief decode mnemonic sentence to the entropy.
 *
 * @param[in] ms_strs A string of mnemonic sentence
 * @param[in] lan The language of the mnemonic sentence
 * @param[out] entropy the output buffer, should bigger than 33 bytes(ENT+CS)
 * @param[in] ent_len the size of the entropy buffer
 * @return size_t the bytes written to output buffer, 0 on failed.
 */
size_t mnemonic_decode(char ms_strs[], ms_lan_t lan, byte_t entropy[], size_t ent_len);

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
int mnemonic_encode(byte_t const entropy[], uint32_t ent_len, ms_lan_t lan, char ms_out[], size_t ms_len);

#ifdef __cplusplus
}
#endif

#endif  // EN_WALLET_BIP39

#endif  // __WALLET_BIP39_H__
