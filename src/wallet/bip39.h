// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __WALLET_BIP39_H__
#define __WALLET_BIP39_H__

#ifdef EN_WALLET_BIP39

#include <stdint.h>

#include "core/types.h"

typedef enum {
  MS_LAN_EN,
  MS_LAN_JA,
  MS_LAN_KO,
  MS_LAN_ES,
  MS_LAN_ZH_HANT,
  MS_LAN_ZH_HANS,
  MS_LAN_FR,
  MS_LAN_IT,
  MS_LAN_CS,
  MS_LAN_PT,
} ms_lan_t;

#ifdef __cplusplus
extern "C" {
#endif

// void mnemonic_to_seed();

int mnemonic_from_seed(byte_t const seed[], uint32_t seed_len, ms_lan_t lan, char out_str[], size_t out_len);

#ifdef __cplusplus
}
#endif

#endif  // EN_WALLET_BIP39

#endif  // __WALLET_BIP39_H__
