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
 * @brief Parse milestone latest response object
 * @param[in] data Data to parse
 * @param[out] res Parsed response object
 * @return 0 if success
 */
int parse_milestone_latest(char *data, milestone_latest_t *res);

#ifdef __cplusplus
}
#endif

#endif