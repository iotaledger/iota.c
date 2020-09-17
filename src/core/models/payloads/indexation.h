#ifndef __CORE_MODELS_PL_INDEXATION_H__
#define __CORE_MODELS_PL_INDEXATION_H__

#include <stdint.h>

#include "core/types.h"
#include "utarray.h"

typedef struct {
  payload_t type;  // Must be set to 2
  char *index;     // The index key of the message
  byte_t *data;    // Data we are attaching
} indexation_t;

typedef UT_array indexation_list_t;

/**
 * @brief loops indexation list
 *
 */
#define UNSIGNED_DATA_LIST_FOREACH(in, elm) \
  for (elm = (indexation_t *)utarray_front(in); elm != NULL; elm = (indexation_t *)utarray_next(in, elm))

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocates an indexation list object.
 *
 * @return indexation_list_t* a pointer to indexation_list_t object
 */
indexation_list_t *indexation_list_new();

/**
 * @brief Appends an indexation element to the list.
 *
 * @param[in] list The indexation list
 * @param[in] index An indexation element to be appended to the list.
 */
static void indexation_list_push(indexation_list_t *list, indexation_t const *const index) {
  utarray_push_back(list, index);
}

/**
 * @brief Removes an indexation element from tail.
 *
 * @param[in] list The indexation list
 */
static void indexation_list_pop(indexation_list_t *list) { utarray_pop_back(list); }

/**
 * @brief Gets indexation list size
 *
 * @param[in] list An indexation_list_t object
 * @return size_t
 */
static size_t indexation_list_len(indexation_list_t *list) { return utarray_len(list); }

/**
 * @brief Gets an indexation element from list by given index.
 *
 * @param[in] list An indexation list object
 * @param[in] index The index of the element
 * @return indexation_t*
 */
static indexation_t *indexation_list_at(indexation_list_t *list, size_t index) {
  // return NULL if not found.
  return (indexation_t *)utarray_eltptr(list, index);
}

/**
 * @brief Frees an indexation list.
 *
 * @param[in] list An indexation list object.
 */
static void indexation_list_free(indexation_list_t *list) { utarray_free(list); }

#ifdef __cplusplus
}
#endif

#endif
