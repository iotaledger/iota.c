#ifndef __CORE_MODELS_PL_TX_H__
#define __CORE_MODELS_PL_TX_H__

#include <stdint.h>
#include <stdlib.h>

#include "core/address.h"
#include "core/types.h"

static const uint64_t MAX_IOTA_SUPPLY = 2779530283277761;

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

/**
 * @brief Transaction Essence, the essence data making up a transaction by defining its inputs and outputs and an
 * optional payload.
 *
 */
typedef struct {
  uint8_t tx_type;        // Set to value 0 to denote a Transaction Essence.
  uint16_t input_count;   // The amount of inputs proceeding.
  uint16_t output_count;  // The amount of outputs proceeding.
  uint32_t payload_len;   // The length in bytes of the optional payload.
  void* inputs;           // any of UTXO input
  void* outputs;          // any of UTXO output
  void* payload;          // an optional payload
} transaction_essence_t;

/**
 * @brief A Transaction payload is made up of two parts:
 * 1. The The Transaction Essence part which contains the inputs, outputs and an optional embedded payload.
 * 2. The Unlock Blocks which unlock the Transaction Essence's inputs. In case the unlock block contains a signature, it
 * signs the entire Transaction Essence part.
 *
 */
typedef struct {
  payload_t type;                  // Set to value 0 to denote a Transaction payload.
  uint32_t unlock_blocks_count;    // The count of unlock blocks proceeding. Must match count of inputs specified.
  transaction_essence_t* essence;  // Describes the essence data making up a transaction by defining its inputs and
                                   // outputs and an optional payload.
  void* unlock_blocks;             // Defines an unlock block containing signature(s) unlocking input(s).
} transaction_payload_t;

#ifdef __cplusplus
extern "C" {
#endif

void tx_essence_new();
void tx_essence_add_input();
void tx_essence_add_output();
void tx_essence_serialize();
void tx_essence_free();

void tx_block_new();
void tx_block_add();
void tx_block_serialize();
void tx_block_free();

void tx_payload_new();
void tx_payload_serialize();
void tx_payload_free();

#ifdef __cplusplus
}
#endif

#endif
