// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __SUB_MILESTONE_LATEST_H__
#define __SUB_MILESTONE_LATEST_H__

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Stores timestamp and index
 *
 */
typedef struct {
  uint64_t timestamp;
  uint32_t index;
} milestone_latest_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocates milestone latest response object
 * @return res_balance_t*
 */
milestone_latest_t *res_milestone_latest_new(void);

/**
 * @brief Frees a milestone latest object
 * @param[in] res A response object
 */
void res_milestone_latest_free(milestone_latest_t *res);

/**
 * @brief Allocates balance response object
 * @param[in] data Data to parse
 * @param[out] res Parsed response object
 * @return 0 if success
 */
int parse_milestone_latest(char *data, milestone_latest_t *res);

#ifdef __cplusplus
}
#endif

#endif