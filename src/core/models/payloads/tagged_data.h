// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_PL_TAGGED_DATA_H__
#define __CORE_MODELS_PL_TAGGED_DATA_H__

#include <stdint.h>

#include "core/utils/byte_buffer.h"

/**
 * @brief Tagged data structure
 *
 * The payload type of tagged data is 5
 */
typedef struct {
  byte_buf_t *tag;   ///< The tag of the data
  byte_buf_t *data;  ///< Binary data
} tagged_data_payload_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create a tagged data object with tag and binary data
 *
 * @param[in] tag The binary tag in tagged data payload
 * @param[in] tag_len The length of the binary tag
 * @param[in] data The binary data in tagged data payload
 * @param[in] data_len The length of the binary data
 * @return tagged_data_payload_t* A pointer to tagged data object
 */
tagged_data_payload_t *tagged_data_new(byte_t tag[], uint8_t tag_len, byte_t data[], uint32_t data_len);

/**
 * @brief Free a tagged data object
 *
 * @param[in] tagged_data A tagged data object
 */
void tagged_data_free(tagged_data_payload_t *tagged_data);

/**
 * @brief Get a serialized length of a tagged data
 *
 * @param[in] tagged_data A tagged data object
 * @return size_t The number of bytes of serialized data
 */
size_t tagged_data_serialize_len(tagged_data_payload_t *tagged_data);

/**
 * @brief Serialize a tagged data to a binary data
 *
 * @param[in] tagged_data A tagged data object
 * @param[out] buf A buffer holds the serialized data
 * @param[in] buf_len The length of buffer
 * @return size_t The bytes written is returned, 0 on errors
 */
size_t tagged_data_serialize(tagged_data_payload_t *tagged_data, byte_t buf[], size_t buf_len);

/**
 * @brief Deserialize a binary data to a tagged data object
 *
 * @param[in] buf The block data in binary
 * @param[in] buf_len The length of the data
 * @return tagged_data_payload_t* or NULL on failure
 */
tagged_data_payload_t *tagged_data_deserialize(byte_t buf[], size_t buf_len);

/**
 * @brief Clone tagged data object, it should be freed after use.
 *
 * @param[in] tagged_data tagged data object for clone
 * @return tagged_data_payload_t* New tagged data object
 */
tagged_data_payload_t *tagged_data_clone(tagged_data_payload_t const *const tagged_data);

/**
 * @brief Print a tagged data object
 *
 * @param[in] tagged_data A tagged data object
 * @param[in] indentation Tab indentation when printing a tagged data
 */
void tagged_data_print(tagged_data_payload_t *tagged_data, uint8_t indentation);

#ifdef __cplusplus
}
#endif

#endif
