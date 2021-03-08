// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_PL_INDEXATION_H__
#define __CORE_MODELS_PL_INDEXATION_H__

#include <stdint.h>

#include "core/types.h"
#include "core/utils/byte_buffer.h"

#define MAX_INDEXCATION_INDEX_BYTES 64

/**
 * @brief Indexation data structure
 *
 * The payload type of indexation is 2
 */
typedef struct {
  byte_buf_t *index;  ///< The index key of the message
  byte_buf_t *data;   ///< Data we are attaching
} indexation_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocate indexation payload
 *
 * @return indexation_t*
 */
indexation_t *indexation_new();

/**
 * @brief Free an indexation payload
 *
 * @param[in] idx An indexation payload object
 */
void indexation_free(indexation_t *idx);

/**
 * @brief Create an indexation payload with index and data
 *
 * @param[in] index An ASCII string
 * @param[in] data A binary array
 * @param[in] data_len The length of data
 * @return indexation_t* A pointer to indexation payload object
 */
indexation_t *indexation_create(char const *index, byte_t data[], uint32_t data_len);

/**
 * @brief Get the serialized length of indexation payload
 *
 * @param[in] idx An indexation payload object
 * @return size_t The expect size of serialied data
 */
size_t indexaction_serialize_length(indexation_t *idx);

/**
 * @brief Serialize an indexation payload
 *
 * @param[in] idx
 * @param[out] buf
 * @return size_t
 */
size_t indexation_payload_serialize(indexation_t *idx, byte_t buf[]);

#ifdef __cplusplus
}
#endif

#endif
