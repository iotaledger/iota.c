// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>

#include "client/api/json_parser/inputs/inputs.h"
#include "client/api/json_parser/json_keys.h"
#include "client/api/json_parser/outputs/outputs.h"
#include "client/api/json_parser/payloads/payloads.h"
#include "client/api/json_parser/unlock_blocks.h"
#include "core/models/payloads/tagged_data.h"
#include "core/utils/macros.h"

static cJSON* json_tx_essence_serialize(transaction_essence_t* es) {
  /*
  {
    "type": 1,
    "networkId": "8453507715857476362",
    "inputs": input_array,
    "inputsCommitment": "0x9f0a1533b91ad7551645dd07d1c21833fff81e74af492af0ca6d99ab7f63b5c9",
    "outputs": output_array,
    "payload": payload object
  }
  */

  cJSON* es_obj = NULL;
  cJSON* input_arr = NULL;
  cJSON* output_arr = NULL;
  cJSON* payload_obj = NULL;

  if (!es) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  if (es->tx_type != TRANSACTION_ESSENCE_TYPE) {
    printf("[%s:%d] invalid transaction essence\n", __func__, __LINE__);
    return NULL;
  }

  // create essence object
  if ((es_obj = cJSON_CreateObject()) == NULL) {
    printf("[%s:%d] creating tx essence object failed\n", __func__, __LINE__);
    return NULL;
  }

  // "type": 1 to denote a Transaction Essence.
  if (!cJSON_AddNumberToObject(es_obj, JSON_KEY_TYPE, es->tx_type)) {
    printf("[%s:%d] add tx type failed\n", __func__, __LINE__);
    cJSON_Delete(es_obj);
    return NULL;
  }

  // network ID
  char network_id[65] = {};
  sprintf(network_id, "%" PRIu64 "", es->network_id);
  if (!cJSON_AddStringToObject(es_obj, JSON_KEY_NET_ID, network_id)) {
    printf("[%s:%d] creating network ID failed\n", __func__, __LINE__);
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

  // inputs commitment
  char inputs_commitment_str[JSON_STR_WITH_PREFIX_BYTES(sizeof(es->inputs_commitment))] = {};
  if (bin_2_hex(es->inputs_commitment, sizeof(es->inputs_commitment), JSON_HEX_ENCODED_STRING_PREFIX,
                inputs_commitment_str, sizeof(inputs_commitment_str)) != 0) {
    printf("[%s:%d] convert inputs commitment to hex string error\n", __func__, __LINE__);
    cJSON_Delete(es_obj);
    return NULL;
  }
  if (!cJSON_AddStringToObject(es_obj, JSON_KEY_INPUTS_COMMITMENT, inputs_commitment_str)) {
    printf("[%s:%d] add inputs commitment to essence error\n", __func__, __LINE__);
    cJSON_Delete(es_obj);
    return NULL;
  }

  // output array
  if ((output_arr = json_outputs_serialize(es->outputs)) == NULL) {
    printf("[%s:%d] add outputs failed\n", __func__, __LINE__);
    cJSON_Delete(es_obj);
    return NULL;
  }
  cJSON_AddItemToObject(es_obj, JSON_KEY_OUTPUTS, output_arr);

  // optional payload
  if (es->payload) {
    if ((payload_obj = json_tagged_serialize(es->payload)) == NULL) {
      printf("[%s:%d] add payload failed\n", __func__, __LINE__);
      cJSON_Delete(es_obj);
      return NULL;
    }
    cJSON_AddItemToObject(es_obj, JSON_KEY_PAYLOAD, payload_obj);
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

static int json_essence_payload_deserialize(cJSON* essence_payload, tagged_data_payload_t** tagged_data,
                                            uint32_t* payload_len) {
  if (!essence_payload || *tagged_data != NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // type
  uint8_t type;
  if (json_get_uint8(essence_payload, JSON_KEY_TYPE, &type) != JSON_OK) {
    printf("[%s:%d]: getting %s json uint8 failed\n", __func__, __LINE__, JSON_KEY_TYPE);
    return -1;
  }

  switch (type) {
    case CORE_MESSAGE_PAYLOAD_TAGGED:
      if (json_tagged_deserialize(essence_payload, tagged_data) != 0) {
        printf("[%s:%d] Can not deserialize tagged data\n", __func__, __LINE__);
        return -1;
      }
      *payload_len = tagged_data_serialize_len(*tagged_data);
      break;
    default:
      printf("[%s:%d] Unsupported payload type\n", __func__, __LINE__);
      return -1;
  }

  return 0;
}

static int milestone_signatures_deserialize(cJSON* payload, UT_array* signatures) {
  if (!payload || !signatures) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // signatures array
  cJSON* sig_obj = cJSON_GetObjectItemCaseSensitive(payload, JSON_KEY_SIGNATURES);
  if (!cJSON_IsArray(sig_obj)) {
    printf("[%s:%d]: %s is not an object\n", __func__, __LINE__, JSON_KEY_SIGNATURES);
    return -1;
  }

  cJSON* elm = NULL;
  cJSON_ArrayForEach(elm, sig_obj) {
    byte_t sig_block[ED25519_SIGNATURE_BLOCK_BYTES] = {};
    sig_block[0] = 0;  // denote ed25519 signature
    // public key
    if (json_get_hex_str_to_bin(elm, JSON_KEY_PUB_KEY, sig_block + 1, ED_PUBLIC_KEY_BYTES) != JSON_OK) {
      printf("[%s:%d]: getting %s json string failed\n", __func__, __LINE__, JSON_KEY_PUB_KEY);
      return -1;
    }
    // signature
    if (json_get_hex_str_to_bin(elm, JSON_KEY_SIG, sig_block + 1 + ED_PUBLIC_KEY_BYTES, ED_SIGNATURE_BYTES) !=
        JSON_OK) {
      printf("[%s:%d]: getting %s json string failed\n", __func__, __LINE__, JSON_KEY_SIG);
      return -1;
    }
    // add signature block into a list
    utarray_push_back(signatures, sig_block);
  }

  return 0;
}

int milestone_deserialize(cJSON* payload, milestone_payload_t* ms) {
  /*
  {
    "protocolVersion": 2,
    "parentMessageIds": [
      "0x596a369aa0de9c1987b28b945375ac8faa8c420c57d17befc6292be70aaea9f3",
      "0x8377782f43faa38ef0a223c870137378e9ec2db57b4d68e0bb9bdeb5d1c4bc3a",
      "0xa3bcf33be3e816c28b295996a31204f64a48aa58adc6f905359e1ffb9ed1b893",
      "0xdbea0f0641f639a689401e85676214c6b51b0823df4414d3201d33aa7fb34aff"
    ],
    "payload": {
      "type": 7,
      "index": 3,
      "timestamp": 1644478549,
      "lastMilestoneId": "0xb1ddd8775e898f15829ad885f0c2cabdbfc08610adf703019edef6f0c24f5eea"
      "parentMessageIds": [
        "0x596a369aa0de9c1987b28b945375ac8faa8c420c57d17befc6292be70aaea9f3",
        "0x8377782f43faa38ef0a223c870137378e9ec2db57b4d68e0bb9bdeb5d1c4bc3a",
        "0xa3bcf33be3e816c28b295996a31204f64a48aa58adc6f905359e1ffb9ed1b893",
        "0xdbea0f0641f639a689401e85676214c6b51b0823df4414d3201d33aa7fb34aff"
      ],
      "confirmedMerkleRoot": "0x9e07623408bcf0b0fb45fa1245f1c1e9787643ca397a1871b391d8732758a7e2",
      "appliedMerkleRoot": "0x0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
      "signatures": [
        { "type": 0,
          "publicKey": "0xd85e5b1590d898d1e0cdebb2e3b5337c8b76270142663d78811683ba47c17c98",
          "signature":
          "0x51306b228a716b656000529b72520fc97cf227197056b289d94d717779cb9749fe9cde77477497cfc594a728ce372b8a7edf233115fb51681e4669f6f4464900"
        },
        { "type": 0,
          "publicKey": "0xd9922819a39e94ddf3907f4b9c8df93f39f026244fcb609205b9a879022599f2",
          "signature":
          "0x1e5fff5396cfa5e9b247ab6cb402c9dfd9b239e6bcaa3c9e370789f3e180599ea267c4b4e61be4864cfae61261af5353b45c2277e1eb3f8bb178211ea7e3e003"
        }
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
  if ((ret = json_get_uint32(payload, JSON_KEY_TIMESTAMP, &ms->timestamp)) != 0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_TIMESTAMP);
    return ret;
  }

  // parsing last milestone ID
  if ((ret = json_get_hex_str_to_bin(payload, JSON_KEY_LAST_MILESTONE_ID, ms->last_milestone_id,
                                     sizeof(ms->last_milestone_id))) != 0) {
    printf("[%s:%d]: parsing %s hex string failed\n", __func__, __LINE__, JSON_KEY_LAST_MILESTONE_ID);
    return ret;
  }

  // parsing parents
  if ((ret = json_string_array_to_bin_array(payload, JSON_KEY_PARENT_IDS, ms->parents, IOTA_MESSAGE_ID_BYTES)) != 0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_PARENT_IDS);
    return ret;
  }

  // parsing confirmed Merkle root
  if ((ret = json_get_hex_str_to_bin(payload, JSON_KEY_CONFIRMED_MERKLE_ROOT, ms->confirmed_merkle_root,
                                     sizeof(ms->confirmed_merkle_root))) != 0) {
    printf("[%s:%d]: parsing %s hex string failed\n", __func__, __LINE__, JSON_KEY_CONFIRMED_MERKLE_ROOT);
    return ret;
  }

  // parsing applied Merkle root
  if ((ret = json_get_hex_str_to_bin(payload, JSON_KEY_APPLIED_MERKLE_ROOT, ms->applied_merkle_root,
                                     sizeof(ms->applied_merkle_root))) != 0) {
    printf("[%s:%d]: parsing %s hex string failed\n", __func__, __LINE__, JSON_KEY_APPLIED_MERKLE_ROOT);
    return ret;
  }

  // parsing metadata
  if (cJSON_GetObjectItemCaseSensitive(payload, JSON_KEY_METADATA)) {
    ms->metadata = byte_buf_new();
    if ((ret = json_get_bin_buf_str(payload, JSON_KEY_METADATA, ms->metadata)) != 0) {
      printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_METADATA);
      return ret;
    }
  }

  // parsing signatures
  if ((ret = milestone_signatures_deserialize(payload, ms->signatures)) != 0) {
    printf("[%s:%d]: parsing milestone signatures failed\n", __func__, __LINE__);
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
    // network Id
    char str_buff[32];
    if ((json_get_string(essence_obj, JSON_KEY_NET_ID, str_buff, sizeof(str_buff))) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_NET_ID);
      return -1;
    }
    sscanf(str_buff, "%" SCNu64, &tx->essence->network_id);

    // inputs array
    cJSON* inputs_obj = cJSON_GetObjectItemCaseSensitive(essence_obj, JSON_KEY_INPUTS);
    if (cJSON_IsArray(inputs_obj)) {
      if (json_inputs_deserialize(inputs_obj, &tx->essence->inputs) != 0) {
        return -1;
      }
    } else {
      printf("[%s:%d]: %s is not an array\n", __func__, __LINE__, JSON_KEY_INPUTS);
      return -1;
    }

    //  inputs commitment
    if (json_get_hex_str_to_bin(essence_obj, JSON_KEY_INPUTS_COMMITMENT, tx->essence->inputs_commitment,
                                sizeof(tx->essence->inputs_commitment)) != JSON_OK) {
      printf("[%s:%d]: getting %s json string failed\n", __func__, __LINE__, JSON_KEY_INPUTS_COMMITMENT);
      return -1;
    }

    // outputs array
    cJSON* outputs_obj = cJSON_GetObjectItemCaseSensitive(essence_obj, JSON_KEY_OUTPUTS);
    if (cJSON_IsArray(outputs_obj)) {
      if (json_outputs_deserialize(outputs_obj, &tx->essence->outputs) != 0) {
        return -1;
      }
    } else {
      printf("[%s:%d]: %s is not an array\n", __func__, __LINE__, JSON_KEY_OUTPUTS);
      return -1;
    }

    // payload in an essence
    cJSON* payload_obj = cJSON_GetObjectItemCaseSensitive(essence_obj, JSON_KEY_PAYLOAD);
    if (!cJSON_IsNull(payload_obj)) {
      if (json_essence_payload_deserialize(payload_obj, (tagged_data_payload_t**)(&tx->essence->payload),
                                           &tx->essence->payload_len) != 0) {
        return -1;
      }
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
    "type": 6,
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

  // "type": 6,
  if (!cJSON_AddNumberToObject(tx_payload, JSON_KEY_TYPE, CORE_MESSAGE_PAYLOAD_TRANSACTION)) {
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

cJSON* json_tagged_serialize(tagged_data_payload_t* tagged_data) {
  /*
  {
    "type": 5,
    "tag": "0x484f524e455420464155434554"
    "data": "0x494f5441202d2041206e6577206461776e0a436f756e743a203138393030350a5032c2b573"
  }
  */
  cJSON* tagged_data_payload = NULL;

  if (!tagged_data) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  // create payload object
  if ((tagged_data_payload = cJSON_CreateObject()) == NULL) {
    printf("[%s:%d] creating tagged data payload object failed\n", __func__, __LINE__);
    return NULL;
  }

  // "type": 5,
  if (!cJSON_AddNumberToObject(tagged_data_payload, JSON_KEY_TYPE, CORE_MESSAGE_PAYLOAD_TAGGED)) {
    printf("[%s:%d] add payload type failed\n", __func__, __LINE__);
    cJSON_Delete(tagged_data_payload);
    return NULL;
  }

  // tag
  if (tagged_data->tag) {
    char tag_str[JSON_STR_WITH_PREFIX_BYTES(TAGGED_DATA_TAG_MAX_LENGTH_BYTES)] = {0};
    if (bin_2_hex(tagged_data->tag->data, tagged_data->tag->len, JSON_HEX_ENCODED_STRING_PREFIX, tag_str,
                  sizeof(tag_str)) != 0) {
      printf("[%s:%d] bin to hex tag conversion failed\n", __func__, __LINE__);
      cJSON_Delete(tagged_data_payload);
      return NULL;
    }
    if (!cJSON_AddStringToObject(tagged_data_payload, JSON_KEY_TAG, tag_str)) {
      printf("[%s:%d] add tag failed\n", __func__, __LINE__);
      cJSON_Delete(tagged_data_payload);
      return NULL;
    }
  }

  // data
  if (tagged_data->data) {
    char* data_str = malloc(JSON_STR_WITH_PREFIX_BYTES(tagged_data->data->len));
    if (!data_str) {
      printf("[%s:%d] OOM\n", __func__, __LINE__);
      cJSON_Delete(tagged_data_payload);
      return NULL;
    }

    if (bin_2_hex(tagged_data->data->data, tagged_data->data->len, JSON_HEX_ENCODED_STRING_PREFIX, data_str,
                  JSON_STR_WITH_PREFIX_BYTES(tagged_data->data->len)) != 0) {
      printf("[%s:%d] bin to hex data conversion failed\n", __func__, __LINE__);
      cJSON_Delete(tagged_data_payload);
      free(data_str);
      return NULL;
    }
    if (!cJSON_AddStringToObject(tagged_data_payload, JSON_KEY_DATA, data_str)) {
      printf("[%s:%d] add data type failed\n", __func__, __LINE__);
      cJSON_Delete(tagged_data_payload);
      free(data_str);
      return NULL;
    }
    free(data_str);
  } else {
    // add a null data to tagged data
    if (!cJSON_AddNullToObject(tagged_data_payload, JSON_KEY_DATA)) {
      printf("[%s:%d] add null data payload failed\n", __func__, __LINE__);
      cJSON_Delete(tagged_data_payload);
      return NULL;
    }
  }

  return tagged_data_payload;
}

int json_tagged_deserialize(cJSON* payload, tagged_data_payload_t** tagged_data) {
  if (!payload || *tagged_data != NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // tag
  cJSON* json_tag = cJSON_GetObjectItemCaseSensitive(payload, JSON_KEY_TAG);
  if (json_tag == NULL) {
    printf("[%s:%d] JSON key not found: %s\n", __func__, __LINE__, JSON_KEY_TAG);
    return -1;
  }

  // data
  cJSON* json_data = cJSON_GetObjectItemCaseSensitive(payload, JSON_KEY_DATA);
  if (json_data == NULL) {
    printf("[%s:%d] JSON key not found: %s\n", __func__, __LINE__, JSON_KEY_DATA);
    return -1;
  }

  // create a new tagged data
  if (cJSON_IsString(json_tag) && cJSON_IsString(json_data)) {
    byte_buf_t* tag = byte_buf_new();
    if (json_get_bin_buf_str(payload, JSON_KEY_TAG, tag) != 0) {
      printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_TAG);
      return -1;
    }

    byte_buf_t* metadata = byte_buf_new();
    if (json_get_bin_buf_str(payload, JSON_KEY_DATA, metadata) != 0) {
      printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_DATA);
      byte_buf_free(tag);
      return -1;
    }

    *tagged_data = tagged_data_new(tag->data, tag->len, metadata->data, metadata->len);
    if (!*tagged_data) {
      printf("[%s:%d]: can not create a new tagged data payload\n", __func__, __LINE__);
      byte_buf_free(tag);
      byte_buf_free(metadata);
      return -1;
    }
    byte_buf_free(tag);
    byte_buf_free(metadata);
  } else {
    printf("[%s:%d] tag or data is not a string\n", __func__, __LINE__);
    return -1;
  }

  return 0;
}
