#ifndef __CORE_MODELS_MESSAGE_H__
#define __CORE_MODELS_MESSAGE_H__

#include <stdint.h>
#include <stdlib.h>

#include "core/models/payloads/indexation.h"
#include "core/models/payloads/milestone.h"
#include "core/models/payloads/transaction.h"
#include "core/types.h"

#define IOTA_MESSAGE_ID_BYTES 32  // message hash ID
#define IOTA_MESSAGE_ID_HEX_BYTES (IOTA_MESSAGE_ID_BYTES * 2)

typedef union {
  indexation_t *indexation;
  milestone_t *milestone;
  transaction_payload_t *tx;
} payload_u;

typedef struct {
  uint64_t network_id;  // Network identifier. It is first 8 bytes of the `BLAKE2b-256` hash of the concatenation of the
                        // network type and the protocol version string.
  byte_t parent1[IOTA_MESSAGE_ID_BYTES];  // The 1st parent the message references.
  byte_t parent2[IOTA_MESSAGE_ID_BYTES];  // The 2nd parent the message references.
  payload_u pyaload;                      // One of payload type
  uint64_t nonce;                         // The nonce which lets this message fulfill the Proof-of-Work requirement.
} core_message_t;

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif
