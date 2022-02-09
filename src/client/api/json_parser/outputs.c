// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/json_parser/outputs.h"
#include "client/api/json_parser/output_alias.h"
#include "client/api/json_parser/output_extended.h"
#include "client/api/json_parser/output_foundry.h"
#include "client/api/json_parser/output_nft.h"

/*
  Example for extended output:
  "outputs": [
    { "type": 3,
      "amount": 10000000,
      "nativeTokens": [],
      "unlockConditions": [],
      "featureBlocks": []
    }
  ],
*/
int json_outputs_deserialize(cJSON *essence_obj, transaction_essence_t *essence) {
  if (essence_obj == NULL || essence == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // outputs array
  cJSON *outputs_obj = cJSON_GetObjectItemCaseSensitive(essence_obj, JSON_KEY_OUTPUTS);
  if (!cJSON_IsArray(outputs_obj)) {
    printf("[%s:%d]: %s is not an array object\n", __func__, __LINE__, JSON_KEY_OUTPUTS);
    return -1;
  }

  cJSON *elm = NULL;
  cJSON_ArrayForEach(elm, outputs_obj) {
    //  type
    uint8_t output_type;
    if (json_get_uint8(elm, JSON_KEY_TYPE, &output_type) != JSON_OK) {
      printf("[%s:%d]: getting %s json uint8 failed\n", __func__, __LINE__, JSON_KEY_TYPE);
      return -1;
    }

    // output
    int res = -1;
    switch (output_type) {
      case OUTPUT_EXTENDED:
        res = json_output_extended_deserialize(elm, essence);
        break;
      case OUTPUT_ALIAS:
        res = json_output_alias_deserialize(elm, essence);
        break;
      case OUTPUT_FOUNDRY:
        res = json_output_foundry_deserialize(elm, essence);
        break;
      case OUTPUT_NFT:
        res = json_output_nft_deserialize(elm, essence);
        break;
      default:
        printf("[%s:%d] Unsupported output block type\n", __func__, __LINE__);
        return -1;
    }

    if (res == -1) {
      printf("[%s:%d] Can not deserialize transaction output\n", __func__, __LINE__);
      return -1;
    }
  }

  return 0;
}

cJSON *json_outputs_serialize(utxo_outputs_list_t *outputs) {
  // TODO
  return NULL;
}
