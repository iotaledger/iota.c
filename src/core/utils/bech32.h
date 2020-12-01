// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_UTILS_BECH32_H__
#define __CORE_UTILS_BECH32_H__

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief bech32 encode
 *
 * @param[out] output The output bech32 string
 * @param[in] hrp A human-readable string
 * @param[in] data The encode data in bytes
 * @param[in] data_len The length of data
 * @return int 1 on success
 */
int bech32_encode(char *output, const char *hrp, const uint8_t *data, size_t data_len);

/**
 * @brief bech32 decode
 *
 * @param[out] hrp The human-readable part
 * @param[out] data The data in bytes
 * @param[out] data_len The length of data
 * @param[in] input A bech32 string
 * @return int 1 on success
 */
int bech32_decode(char *hrp, uint8_t *data, size_t *data_len, const char *input);

#ifdef __cplusplus
}
#endif

#endif
