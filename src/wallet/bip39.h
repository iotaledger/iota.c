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

/**
 * @brief Converts mnemonic sentence to an IOTA seed.
 *
 * @param[in] ms_strs A string of mnemonic sentence
 * @param[in] lan The language of the mnemonic sentence
 * @param[in] seed the output buffer, should bigger than 33 bytes(ENT+CS)
 * @param[in] seed_len the size of the output buffer
 * @return size_t the bytes written to output buffer, 0 on failed.
 */
size_t mnemonic_to_seed(char ms_strs[], ms_lan_t lan, byte_t seed[], size_t seed_len);

/**
 * @brief Gets mnemonic sentence from a given(IOTA) seed.
 *
 * @param[in] seed the input seed(entroty)
 * @param[in] seed_len the length of seed(entroty), should be one of 16, 20, 24, 28, 32.
 * @param[in] lan The expected language of mnemonic sentence
 * @param[out] buf_out The output string of mnemonic sentence
 * @param[in] buf_len the output buffer length
 * @return int 0 on success
 */
int mnemonic_from_seed(byte_t const seed[], uint32_t seed_len, ms_lan_t lan, char buf_out[], size_t buf_len);

#ifdef __cplusplus
}
#endif

#endif  // EN_WALLET_BIP39

#endif  // __WALLET_BIP39_H__
