#ifndef __CORE_MODELS_PL_INDEXATION_H__
#define __CORE_MODELS_PL_INDEXATION_H__

#include <stdint.h>

#include "core/types.h"
#include "core/utils/byte_buffer.h"

typedef struct {
  payload_t type;     // Must be set to 2
  byte_buf_t *index;  // The index key of the message
  byte_buf_t *data;   // Data we are attaching
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
 * @param[in] index The index string
 * @param[in] data The data in bytes
 * @param[in] data_size The length of data
 * @return indexation_t*
 */
indexation_t *indexation_create(char index[], byte_t *data, size_t data_size);

#ifdef __cplusplus
}
#endif

#endif
