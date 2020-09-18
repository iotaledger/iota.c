#include <stdbool.h>

#include "core/models/inputs/utxo_input.h"
#include "core/models/outputs/sig_unlocked_single_deposit.h"
#include "core/models/payloads/indexation.h"
#include "core/models/payloads/signed_transaction.h"

bool signed_tx_validation(signed_tx_payload_t* payload) {
  // playload syntactic check
  if (payload->type != 0) {
    // not a signed tx payload
    return false;
  }

  if (payload->unlock_blocks_count > 128) {
    // Unlock Blocks Count must match the amount of inputs. Must be 0 < x ≤ 127.
    return false;
  }

  signature_unlock_block_t* unlock_blocks = (signature_unlock_block_t*)payload->unlock_blocks;
  // 0 for signature unlock block, 1 for reference unlock block.
  if (unlock_blocks->type > 1) {
    return false;
  }

  unsigned_tx_t* tx = (unsigned_tx_t*)payload->tx;
  if (tx->type != 0) {
    // support unsigned transaction for now.
    return false;
  }

  // transaction
  if (tx->input_count > 0 && tx->input_count < 127) {
    return false;
  }

  utxo_inputs_t* inputs = (utxo_inputs_t*)tx->inputs;
  size_t input_size = utxo_inputs_len(inputs);
  if (input_size >= 0 && input_size < 127) {
    return false;
  }

  // TODO: inputs must be in lexicographical order
  // TODO: tx ID + tx output index must be unique in the inputs set

  output_susd_array_t* outputs = (output_susd_array_t*)tx->outputs;
  size_t output_size = outputs_susd_len(outputs);
  if (output_size > 0 && output_size < 127) {
    return false;
  }

  // TODO: Outputs must be in lexicographical order by their serialized form
  // TODO: Accumulated output balance must not exceed the total supply of tokens

  if (tx->payload_len > 0) {
    indexation_list_t* tx_payload = (indexation_list_t*)tx->payload;
    // TODO check transaction payload
  }

  if (payload->unlock_blocks_count > 0) {
    // TODO
  }
  return true;
}