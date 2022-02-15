// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/json_parser/payloads.h"
#include "client/api/json_parser/inputs.h"
#include "client/api/json_parser/json_keys.h"
#include "client/api/json_parser/outputs.h"
#include "client/api/json_parser/unlock_blocks.h"

static cJSON* json_tx_essence_serialize(transaction_essence_t* es) {
  /*
  {
    "type": 0,
    "inputs": input_array
    "outputs": output_array
    "payload": null
  }
  */

  cJSON* es_obj = NULL;
  cJSON* input_arr = NULL;
  cJSON* output_arr = NULL;

  if (!es) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  if (es->tx_type != 0) {
    printf("[%s:%d] invalid transaction essence\n", __func__, __LINE__);
    return NULL;
  }

  // create essence object
  if ((es_obj = cJSON_CreateObject()) == NULL) {
    printf("[%s:%d] creating tx essence object failed\n", __func__, __LINE__);
    return NULL;
  }

  // "type": 0 to denote a Transaction Essence.
  if (!cJSON_AddNumberToObject(es_obj, JSON_KEY_TYPE, 0)) {
    printf("[%s:%d] add tx type failed\n", __func__, __LINE__);
    cJSON_Delete(es_obj);
    return NULL;
  }

  // input array
  if ((input_arr = json_inputs_serialize(es->inputs)) == NULL) {
    printf("[%s:%d] add inputs failed\n", __func__, __LINE__);
    cJSON_Delete(es_obj);
    return NULL;
  }
  cJSON_AddItemToObject(es_obj, JSON_KEY_INPUTS, input_arr);

  // output array
  if ((output_arr = json_outputs_serialize(es->outputs)) == NULL) {
    printf("[%s:%d] add outputs failed\n", __func__, __LINE__);
    cJSON_Delete(es_obj);
    return NULL;
  }
  cJSON_AddItemToObject(es_obj, JSON_KEY_OUTPUTS, output_arr);

  // optional payload
  if (es->payload) {
    // TODO support payload in a tx essence
    printf("[%s:%d] TODO: support payload in tx essence\n", __func__, __LINE__);
  } else {
    // add a null payload to essence
    if (!cJSON_AddNullToObject(es_obj, JSON_KEY_PAYLOAD)) {
      printf("[%s:%d] add null payload failed\n", __func__, __LINE__);
      cJSON_Delete(es_obj);
      return NULL;
    }
  }

  return es_obj;
}

int milestone_deserialize(cJSON* payload, milestone_t* ms) {
  /*
  {
    "networkId": "8453507715857476362",
    "parentMessageIds": [
      "596a369aa0de9c1987b28b945375ac8faa8c420c57d17befc6292be70aaea9f3",
      "8377782f43faa38ef0a223c870137378e9ec2db57b4d68e0bb9bdeb5d1c4bc3a",
      "a3bcf33be3e816c28b295996a31204f64a48aa58adc6f905359e1ffb9ed1b893",
      "dbea0f0641f639a689401e85676214c6b51b0823df4414d3201d33aa7fb34aff"
    ],
    "payload": {
      "type": 1,
      "index": 3,
      "timestamp": 1644478549,
      "parentMessageIds": [
        "596a369aa0de9c1987b28b945375ac8faa8c420c57d17befc6292be70aaea9f3",
        "8377782f43faa38ef0a223c870137378e9ec2db57b4d68e0bb9bdeb5d1c4bc3a",
        "a3bcf33be3e816c28b295996a31204f64a48aa58adc6f905359e1ffb9ed1b893",
        "dbea0f0641f639a689401e85676214c6b51b0823df4414d3201d33aa7fb34aff"
      ],
      "inclusionMerkleProof": "58f3fe3e0727eb7a34a2fe8a7a3d2a1b5b33650c26b34c1955909db3e8a1176c",
      "nextPoWScore": 0,
      "nextPoWScoreMilestoneIndex": 0,
      "publicKeys": [
        "ed3c3f1a319ff4e909cf2771d79fece0ac9bd9fd2ee49ea6c0885c9cb3b1248c",
        "f6752f5f46a53364e2ee9c4d662d762a81efd51010282a75cd6bd03f28ef349c"
      ],
      "receipt": null,
      "signatures": [
        "a6989002bdfcab4eb8ea7144a9a79789ef331c46377ed8036e87a3fac601d1207af5904814bec2d4dc790ff250574b4c33cfd64dadf7bcc085a062e486c7a105",
        "005af6a44ded27650c23457f540576515a1e1549ff50d1279bde77d2dd8802c8676053ec5c0939671db1c2d920b3c557389b19a7f1ad310dc5ed23f840ddfa05"
      ]
    },
    "nonce": "14757395258967713456"
  }
  */

  if (payload == NULL || ms == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  int ret = -1;

  // parsing index
  if ((ret = json_get_uint32(payload, JSON_KEY_INDEX, &ms->index)) != 0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_INDEX);
    return ret;
  }

  // parsing timestamp
  if ((ret = json_get_uint64(payload, JSON_KEY_TIMESTAMP, &ms->timestamp)) != 0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_TIMESTAMP);
    return ret;
  }

  // parsing parents
  if ((ret = json_string_array_to_msg_ids(payload, JSON_KEY_PARENT_IDS, ms->parents)) != 0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_PARENT_IDS);
    return ret;
  }
  // parsing inclusion Merkle proof
  if ((ret = json_get_string(payload, JSON_KEY_INCLUSION_MKL, ms->inclusion_merkle_proof,
                             sizeof(ms->inclusion_merkle_proof))) != 0) {
    printf("[%s:%d]: parsing %s string failed\n", __func__, __LINE__, JSON_KEY_INCLUSION_MKL);
    return ret;
  }

  // parsing next Pow score
  if ((ret = json_get_uint32(payload, JSON_KEY_NEXT_POW_SCORE, &ms->next_pow_score)) != 0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_NEXT_POW_SCORE);
    return ret;
  }

  // parsing next Pow score milestone index
  if ((ret = json_get_uint32(payload, JSON_KEY_NEXT_POW_SCORE_MILESTONE_IDX, &ms->next_pow_score_milestone_index)) !=
      0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_NEXT_POW_SCORE_MILESTONE_IDX);
    return ret;
  }

  // parsing public keys
  if ((ret = json_string_array_to_pub_key(payload, JSON_KEY_PUBLIC_KEYS, ms->pub_keys)) != 0) {
    printf("[%s:%d]: parsing %s array failed\n", __func__, __LINE__, JSON_KEY_PUBLIC_KEYS);
    return ret;
  }

  // parsing receipt
  // TODO parse receipt

  // parsing signatures
  if ((ret = json_string_array_to_signature(payload, JSON_KEY_SIGNATURES, ms->signatures)) != 0) {
    printf("[%s:%d]: parsing %s array failed\n", __func__, __LINE__, JSON_KEY_SIGNATURES);
    return ret;
  }

  return 0;
}

int json_transaction_deserialize(cJSON* payload, transaction_payload_t* tx) {
  if (!payload || !tx) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // parsing essence
  cJSON* essence_obj = cJSON_GetObjectItemCaseSensitive(payload, JSON_KEY_ESSENCE);
  if (essence_obj) {
    // inputs array
    cJSON* inputs_obj = cJSON_GetObjectItemCaseSensitive(essence_obj, JSON_KEY_INPUTS);
    if (cJSON_IsArray(inputs_obj)) {
      if (json_inputs_deserialize(inputs_obj, &tx->essence->inputs)) {
        return -1;
      }
    } else {
      printf("[%s:%d]: %s is not an array\n", __func__, __LINE__, JSON_KEY_INPUTS);
      return -1;
    }

    // outputs array
    cJSON* outputs_obj = cJSON_GetObjectItemCaseSensitive(essence_obj, JSON_KEY_OUTPUTS);
    if (cJSON_IsArray(outputs_obj)) {
      if (json_outputs_deserialize(outputs_obj, &tx->essence->outputs)) {
        return -1;
      }
    } else {
      printf("[%s:%d]: %s is not an array\n", __func__, __LINE__, JSON_KEY_OUTPUTS);
      return -1;
    }

    // payload in an essence
    cJSON* payload_obj = cJSON_GetObjectItemCaseSensitive(essence_obj, JSON_KEY_PAYLOAD);
    if (!cJSON_IsNull(payload_obj)) {
      // TODO
      printf("[%s:%d]: TODO, support payload in an essence\n", __func__, __LINE__);
    }

  } else {
    printf("[%s:%d]: %s not found in the message\n", __func__, __LINE__, JSON_KEY_ESSENCE);
    return -1;
  }

  // unlock blocks
  cJSON* blocks_obj = cJSON_GetObjectItemCaseSensitive(payload, JSON_KEY_UNLOCK_BLOCKS);
  if (cJSON_IsArray(blocks_obj)) {
    if (json_unlock_blocks_deserialize(blocks_obj, &tx->unlock_blocks)) {
      return -1;
    }
  } else {
    printf("[%s:%d]: %s is not an array object\n", __func__, __LINE__, JSON_KEY_UNLOCK_BLOCKS);
    return -1;
  }

  return 0;
}

cJSON* json_transaction_serialize(transaction_payload_t* tx) {
  /*
  {
    "type": 0,
    "essence": essence object
    "unlockBlocks": unlock blocks object
  }
  */
  cJSON* tx_payload = NULL;
  cJSON* essence = NULL;
  cJSON* blocks = NULL;

  if (!tx) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  // create payload object
  if ((tx_payload = cJSON_CreateObject()) == NULL) {
    printf("[%s:%d] creating tx payload object failed\n", __func__, __LINE__);
    return NULL;
  }

  // "type": 0,
  if (!cJSON_AddNumberToObject(tx_payload, JSON_KEY_TYPE, 0)) {
    printf("[%s:%d] add payload type failed\n", __func__, __LINE__);
    cJSON_Delete(tx_payload);
    return NULL;
  }

  // essence
  if ((essence = json_tx_essence_serialize(tx->essence)) == NULL) {
    printf("[%s:%d] create essence object failed\n", __func__, __LINE__);
    cJSON_Delete(tx_payload);
    return NULL;
  }
  cJSON_AddItemToObject(tx_payload, JSON_KEY_ESSENCE, essence);

  // unlocked blocks
  if ((blocks = json_unlock_blocks_serialize(tx->unlock_blocks)) == NULL) {
    printf("[%s:%d] create unlocked blocks object failed\n", __func__, __LINE__);
    cJSON_Delete(tx_payload);
    return NULL;
  }
  cJSON_AddItemToObject(tx_payload, JSON_KEY_UNLOCK_BLOCKS, blocks);

  return tx_payload;
}

// TODO
cJSON* json_tagged_serialize(void* tx) { return NULL; }
