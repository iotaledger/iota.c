#ifndef __MODELS_OUTPUTS_SIG_UNLOCK_H__
#define __MODELS_OUTPUTS_SIG_UNLOCK_H__

#include <stdint.h>

#include "core/address.h"
#include "core/types.h"
#include "utarray.h"

typedef UT_array output_susd_array_t;

typedef struct {
  output_t type;                    // Set to value 0 to denote a SigLockedSingleDeposit.
  byte_t addr[IOTA_ADDRESS_BYTES];  // Ed25519 address
  uint64_t amount;                  // The amount of tokens to deposit with this SigLockedSingleDeposit output.
} sig_unlocked_single_deposit_t;

/**
 * @brief loops signature-unlocked single deposit(susd) list
 *
 */
#define OUTPUTS_SUSD_FOREACH(outs, elm)                                         \
  for (elm = (sig_unlocked_single_deposit_t *)utarray_front(outs); elm != NULL; \
       elm = (sig_unlocked_single_deposit_t *)utarray_next(outs, elm))

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Prints a signature-unlocked single deposit object.
 *
 * @param[in] out A signature-unlocked single deposit object.
 */
void output_susd_print(sig_unlocked_single_deposit_t *out);

/**
 * @brief Allocates a signature-unlocked single deposit list
 *
 * @return output_susd_array_t*
 */
output_susd_array_t *outputs_susd_new();

/**
 * @brief Appends an deposit element to tail.
 *
 * @param[in] outs The output deposit list
 * @param[in] elm A signature-unlocked single deposit element
 */
static void outputs_susd_push(output_susd_array_t *outs, sig_unlocked_single_deposit_t const *const elm) {
  utarray_push_back(outs, elm);
}

/**
 * @brief Removes an deposit element from tail.
 *
 * @param[in] outs The output deposit list
 */
static void outputs_susd_pop(output_susd_array_t *outs) { utarray_pop_back(outs); }

/**
 * @brief Gets output array size
 *
 * @param[in] outs An output_susd_array_t object
 * @return size_t
 */
static size_t outputs_susd_len(output_susd_array_t *outs) { return utarray_len(outs); }

/**
 * @brief Gets an output element from array by given index.
 *
 * @param[in] outs A signature-unlocked single deposit list
 * @param[in] index The index of the element
 * @return sig_unlocked_single_deposit_t*
 */
static sig_unlocked_single_deposit_t *outputs_susd_at(output_susd_array_t *outs, size_t index) {
  // return NULL if not found.
  return (sig_unlocked_single_deposit_t *)utarray_eltptr(outs, index);
}

/**
 * @brief Frees a sig_unlocked_single_deposit_t list.
 *
 * @param[in] outs A signature-unlocked single deposit list
 */
static void outputs_susd_free(output_susd_array_t *outs) { utarray_free(outs); }

/**
 * @brief Prints a sig_unlocked_single_deposit_t list.
 *
 * @param[in] outs A signature-unlocked single deposit list
 */
void outputs_susd_array_print(output_susd_array_t *outs);

#ifdef __cplusplus
}
#endif

#endif