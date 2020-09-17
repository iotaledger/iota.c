#ifndef __MODELS_PAYLOADS_SIGNED_TX_H__
#define __MODELS_PAYLOADS_SIGNED_TX_H__

#include <stdint.h>
#include <stdlib.h>

#include "core/address.h"
#include "core/types.h"

static const uint64_t MAX_IOTA_SUPPLY = 2779530283277761;

typedef struct {
  transaction_t type;     // Set to value 0 to denote an Unsigned Transaction.
  uint16_t input_count;   // The amount of inputs proceeding.
  void *inputs;           // a list of inputs, any of utxo_input
  uint16_t output_count;  // The amount of outputs proceeding.
  void *outputs;          // a list of outputs, any of sig_unlocked_single_deposit_t
  uint32_t payload_len;   // The length in bytes of the optional payload.
  void *payload;          // optional one of unsigned data, signed data, indexation playloads.
} unsigned_tx_t;

typedef struct {
  signature_t type;                      // Set to value 0 to denote an Ed25519 Signature
  byte_t pub_key[ED_PUBLIC_KEY_BYTES];   // The public key of the Ed25519 keypair which is used to verify the signature.
  byte_t signature[ED_SIGNATURE_BYTES];  // The signature signing the serialized Unsigned Transaction.
} ed25519_signature_t;

typedef struct {
  unlock_block_t type;            // Set to value 0 to denote a Signature Unlock Block.
  ed25519_signature_t signature;  // Ed25519 signature
} signature_unlock_block_t;

typedef struct {
  unlock_block_t type;  // Set to value 1 to denote a Reference Unlock Block.
  uint16_t reference;   // Represents the index of a previous unlock block.
} reference_unlock_block_t;

/*
A Signed Transaction payload is made up of two parts:
  * The Unsigned Transaction part which contains the inputs, outputs and an optional embedded payload.
  * The Unlock Blocks which unlock the Unsigned Transaction's inputs. In case the unlock block contains a signature, it
    signs the entire Unsigned Transaction part.
*/
typedef struct {
  payload_t type;                // Set to value 0 to denote a Signed Transaction payload.
  uint32_t unlock_blocks_count;  // The count of unlock blocks proceeding. Must match count of inputs specified.
  void *tx;                      // One of transaction type, ex: unsigned_tx_t
  void *unlock_blocks;           // a list of unlock blocks, any of signature unlock block or reference unlock block
} signed_tx_payload_t;

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif
