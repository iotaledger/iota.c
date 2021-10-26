// Copyright 2020 IOTA Stiftung
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

/**
 * @brief The response argumet for callback
 *
 */
typedef struct {
  bool is_error;  ///< True if error occured
  union {
    char *error;                                    ///< Error message if is_error is True
    milestone_latest_t *received_milestone_latest;  ///< a balance object if is_error is False
  } u;
} res_milestone_latest_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocates balance response object
 * @return res_balance_t*
 */
int sub_milestone_latest(void (*callback)(res_milestone_latest_t *));

#ifdef __cplusplus
}
#endif

#endif