#ifndef __CORE_MODELS_OUTPUTS_SIG_UNLOCK_H__
#define __CORE_MODELS_OUTPUTS_SIG_UNLOCK_H__

#include <stdint.h>

#include "core/address.h"
#include "core/types.h"
#include "utarray.h"

typedef UT_array output_suso_array_t;

typedef struct {
  output_t type;                       // Set to value 0 to denote a SigLockedSingleOutout.
  byte_t addr[ED25519_ADDRESS_BYTES];  // Ed25519 address
  uint64_t amount;                     // The amount of tokens to deposit with this SigLockedSingleOutput output.
} sig_unlocked_single_output_t;

/**
 * @brief loops signature-unlocked single output(suso) list
 *
 */
#define OUTPUTS_SUSO_FOREACH(outs, elm)                                        \
  for (elm = (sig_unlocked_single_output_t *)utarray_front(outs); elm != NULL; \
       elm = (sig_unlocked_single_output_t *)utarray_next(outs, elm))

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Prints a signature-unlocked single output object.
 *
 *
 * @param[in] out A signature-unlocked single output object.
 */
void output_suso_print(sig_unlocked_single_output_t *out);

/**
 * @brief Allocates a signature-unlocked single output list
 *
 * @return output_suso_array_t*
 */
output_suso_array_t *outputs_suso_new();

/**
 * @brief Appends an output element to tail.
 *
 * @param[in] outs The output list
 * @param[in] elm A signature-unlocked single output element
 */
static void outputs_suso_push(output_suso_array_t *outs, sig_unlocked_single_output_t const *const elm) {
  utarray_push_back(outs, elm);
}

/**
 * @brief Removes an output element from tail.
 *
 * @param[in] outs The output list
 */
static void outputs_suso_pop(output_suso_array_t *outs) { utarray_pop_back(outs); }

/**
 * @brief Gets output array size
 *
 * @param[in] outs An output_suso_array_t object
 * @return size_t
 */
static size_t outputs_suso_len(output_suso_array_t *outs) { return utarray_len(outs); }

/**
 * @brief Gets an output element from array by given index.
 *
 * @param[in] outs A signature-unlocked single output list
 * @param[in] index The index of the element
 * @return sig_unlocked_single_output_t*
 */
static sig_unlocked_single_output_t *outputs_suso_at(output_suso_array_t *outs, size_t index) {
  // return NULL if not found.
  return (sig_unlocked_single_output_t *)utarray_eltptr(outs, index);
}

/**
 * @brief Frees a sig_unlocked_single_output_t list.
 *
 * @param[in] outs A signature-unlocked single output list
 */
static void outputs_suso_free(output_suso_array_t *outs) { utarray_free(outs); }

/**
 * @brief Prints a sig_unlocked_single_output_t list.
 *
 * @param[in] outs A signature-unlocked single output list
 */
void outputs_suso_array_print(output_suso_array_t *outs);

#ifdef __cplusplus
}
#endif

#endif