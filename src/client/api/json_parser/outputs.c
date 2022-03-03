// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/json_parser/outputs.h"
#include "client/api/json_parser/output_alias.h"
#include "client/api/json_parser/output_extended.h"
#include "client/api/json_parser/output_foundry.h"
#include "client/api/json_parser/output_nft.h"
#include "utlist.h"

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
int json_outputs_deserialize(cJSON *outputs_obj, utxo_outputs_list_t **outputs) {
  if (outputs_obj == NULL || *outputs != NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
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
      case OUTPUT_EXTENDED: {
        output_extended_t *extended = NULL;
        res = json_output_extended_deserialize(elm, &extended);
        if (res == 0) {
          res = utxo_outputs_add(outputs, NULL, OUTPUT_EXTENDED, extended);
        }
        output_extended_free(extended);
        break;
      }
      case OUTPUT_ALIAS: {
        output_alias_t *alias = NULL;
        res = json_output_alias_deserialize(elm, &alias);
        if (res == 0) {
          res = utxo_outputs_add(outputs, NULL, OUTPUT_ALIAS, alias);
        }
        output_alias_free(alias);
        break;
      }
      case OUTPUT_FOUNDRY: {
        output_foundry_t *foundry = NULL;
        res = json_output_foundry_deserialize(elm, &foundry);
        if (res == 0) {
          res = utxo_outputs_add(outputs, NULL, OUTPUT_FOUNDRY, foundry);
        }
        output_foundry_free(foundry);
        break;
      }
      case OUTPUT_NFT: {
        output_nft_t *nft = NULL;
        res = json_output_nft_deserialize(elm, &nft);
        if (res == 0) {
          res = utxo_outputs_add(outputs, NULL, OUTPUT_NFT, nft);
        }
        output_nft_free(nft);
        break;
      }
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
  cJSON *output_arr = cJSON_CreateArray();
  if (output_arr) {
    // empty list
    if (!outputs) {
      return output_arr;
    }

    // add items to array
    cJSON *item = NULL;
    utxo_outputs_list_t *elm;
    LL_FOREACH(outputs, elm) {
      switch (elm->output->output_type) {
        case OUTPUT_EXTENDED:
          item = json_output_extended_serialize((output_extended_t *)elm->output->output);
          break;
        case OUTPUT_ALIAS:
          item = json_output_alias_serialize((output_alias_t *)elm->output->output);
          break;
        case OUTPUT_FOUNDRY:
          item = json_output_foundry_serialize((output_foundry_t *)elm->output->output);
          break;
        case OUTPUT_NFT:
          item = json_output_nft_serialize((output_nft_t *)elm->output->output);
          break;
        case OUTPUT_SINGLE_OUTPUT:
        case OUTPUT_DUST_ALLOWANCE:
        case OUTPUT_TREASURY:
        default:
          printf("[%s:%d] unsupported output type\n", __func__, __LINE__);
          break;
      }

      if (item) {
        // add item to array
        if (!cJSON_AddItemToArray(output_arr, item)) {
          printf("[%s:%d] add output to outputs array error\n", __func__, __LINE__);
          cJSON_Delete(item);
          cJSON_Delete(output_arr);
          return NULL;
        }
      } else {
        printf("[%s:%d] serialize output error\n", __func__, __LINE__);
        cJSON_Delete(output_arr);
        return NULL;
      }
    }
  }
  return output_arr;
}
