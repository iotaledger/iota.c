#ifndef __CORE_MODELS_INPUTS_UTXO_INPUT_H__
#define __CORE_MODELS_INPUTS_UTXO_INPUT_H__

#include <stdint.h>

#include "core/types.h"
#include "utarray.h"

#define TRANSACTION_ID_BYTES 32

typedef struct {
  input_t type;                        // Set to value 0 to denote a UTXO Input.
  byte_t tx_id[TRANSACTION_ID_BYTES];  // The transaction reference from which the UTXO comes from.
  uint64_t output_index;               // The index of the output on the referenced transaction to consume.
} utxo_input_t;

typedef UT_array utxo_inputs_t;

/**
 * @brief loops utxo input list
 *
 */
#define UTXO_INPUTS_FOREACH(utxo_ins, elm) \
  for (elm = (utxo_input_t *)utarray_front(utxo_ins); elm != NULL; elm = (utxo_input_t *)utarray_next(utxo_ins, elm))

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Prints an utxo input element.
 *
 * @param[in] utxo An utxo input object.
 */
void utxo_input_print(utxo_input_t *utxo);

/**
 * @brief Allocates an utxo input list object.
 *
 * @return utxo_inputs_t* a pointer to utxo_inputs_t object
 */
utxo_inputs_t *utxo_inputs_new();

/**
 * @brief Appends an utxo input element to the list.
 *
 * @param[in] utxo_ins The utxo input list
 * @param[in] utxo An utxo input element to be appended to the list.
 */
static void utxo_inputs_push(utxo_inputs_t *utxo_ins, utxo_input_t const *const utxo) {
  utarray_push_back(utxo_ins, utxo);
}

/**
 * @brief Removes an utxo input element from tail.
 *
 * @param[in] utxo_ins The utxo input list
 */
static void utxo_inputs_pop(utxo_inputs_t *utxo_ins) { utarray_pop_back(utxo_ins); }

/**
 * @brief Gets utxo input size
 *
 * @param[in] utxo_ins An utxo_inputs_t object
 * @return size_t
 */
static size_t utxo_inputs_len(utxo_inputs_t *utxo_ins) { return utarray_len(utxo_ins); }

/**
 * @brief Gets an utxo input element from list by given index.
 *
 * @param[in] utxo_ins An utxo input list object
 * @param[in] index The index of the element
 * @return utxo_input_t*
 */
static utxo_input_t *utxo_inputs_at(utxo_inputs_t *utxo_ins, size_t index) {
  // return NULL if not found.
  return (utxo_input_t *)utarray_eltptr(utxo_ins, index);
}

/**
 * @brief Frees an utxo input list.
 *
 * @param[in] utxo_ins An utxo input list object.
 */
static void utxo_inputs_free(utxo_inputs_t *utxo_ins) { utarray_free(utxo_ins); }

/**
 * @brief Prints an utxo input list.
 *
 * @param[in] utxo_ins An utxo input list object.
 */
void utxo_inputs_print(utxo_inputs_t *utxo_ins);

#ifdef __cplusplus
}
#endif

#endif