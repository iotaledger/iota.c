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

/**
 * @brief Encode IOTA address to bech32 string
 *
 * @param[out] output An output buffer holds bech32 address string
 * @param[in] hrp A string of human-readable prefixe
 * @param[in] addr An address in bytes
 * @param[in] addr_len The length of IOTA address which is 33
 * @return int 1 on success
 */
int iota_addr_bech32_encode(char *output, const char *hrp, const uint8_t *addr, size_t addr_len);

/**
 * @brief Decode a bech32 string to address byte data
 *
 * @param[out] addr_data A buffer holds the address byte data
 * @param[out] addr_len the number bytes of address data
 * @param[in] hrp An expected string of human-readable prefixe
 * @param[in] addr_str A string of bech32 address
 * @return int 1 on success
 */
int iota_addr_bech32_decode(uint8_t *addr_data, size_t *addr_len, const char *hrp, const char *addr_str);

#ifdef __cplusplus
}
#endif

#endif
