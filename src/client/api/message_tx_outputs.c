// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/message_tx_outputs.h"
#include "client/api/json_keys.h"
#include "core/address.h"

static int deser_native_tokens(cJSON *output_obj, UT_array *native_tokens) {
  /*
  "nativeTokens": [
    { "id": "9s8dfzh987shfd098fjhg0b98du",
      "amount": "93847598347598347598347598", }
  ],
  */
  cJSON *tx_native_tokens_obj = cJSON_GetObjectItemCaseSensitive(output_obj, JSON_KEY_NATIVE_TOKENS);

  if (cJSON_IsArray(tx_native_tokens_obj)) {
    cJSON *elm = NULL;
    cJSON_ArrayForEach(elm, tx_native_tokens_obj) {
      cJSON *tx_token_id_obj = cJSON_GetObjectItemCaseSensitive(elm, JSON_KEY_ID);
      cJSON *tx_token_amount_obj = cJSON_GetObjectItemCaseSensitive(elm, JSON_KEY_AMOUNT);

      if (cJSON_IsString(tx_token_id_obj) && cJSON_IsString(tx_token_amount_obj)) {
        tx_native_token_t new_native_token = {};
        memcpy(new_native_token.id, tx_token_id_obj->valuestring, sizeof(new_native_token.id));
        memcpy(&new_native_token.amount, tx_token_amount_obj->valuestring, sizeof(new_native_token.amount));

        // add native token to array
        utarray_push_back(native_tokens, &new_native_token);
      } else {
        printf("[%s:%d] %s or %s is not a string\n", __func__, __LINE__, JSON_KEY_ID, JSON_KEY_AMOUNT);
        return -1;
      }
    }
  } else {
    printf("[%s:%d]: %s is not an array object\n", __func__, __LINE__, JSON_KEY_NATIVE_TOKENS);
    return -1;
  }

  return 0;
}

static char *deser_address(cJSON *json_obj, char const *const json_key) {
  cJSON *tx_address_obj = cJSON_GetObjectItemCaseSensitive(json_obj, json_key);
  if (!tx_address_obj) {
    return NULL;
  }

  cJSON *tx_address_type = cJSON_GetObjectItemCaseSensitive(tx_address_obj, JSON_KEY_TYPE);
  if (tx_address_type && cJSON_IsNumber(tx_address_type)) {
    if (tx_address_type->valueint == ADDRESS_TYPE_ED25519) {
      cJSON *address_obj = cJSON_GetObjectItemCaseSensitive(tx_address_obj, JSON_KEY_ADDR);
      if (cJSON_IsString(address_obj)) {
        return address_obj->valuestring;
      }
    }
  }

  return NULL;
}

static int deser_address_unlock(cJSON *unlock_cond_obj, UT_array *unlock_conditions) {
  /*
  "address": {
    "type": 0,
    "address": "ad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4"
  }
  */
  char *address = deser_address(unlock_cond_obj, JSON_KEY_ADDR);

  if (address) {
    tx_address_unlock_cond_t unlock_address = {};
    memcpy(unlock_address.address, address, sizeof(unlock_address.address));

    // add address unlock to array
    utarray_push_back(unlock_conditions, &unlock_address);
    return 0;
  }

  return -1;
}

static int deser_dust_deposit_return_unlock(cJSON *unlock_cond_obj, UT_array *unlock_conditions) {
  /*
  "address": {
    "type": 0,
    "address": "ad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4"
  },
  "amount": 123123
  */
  char *address = deser_address(unlock_cond_obj, JSON_KEY_ADDR);
  cJSON *tx_amount_obj = cJSON_GetObjectItemCaseSensitive(unlock_cond_obj, JSON_KEY_AMOUNT);

  if (address && cJSON_IsNumber(tx_amount_obj)) {
    tx_dust_deposit_return_unlock_cond_t unlock_dust_deposit_return = {};
    memcpy(unlock_dust_deposit_return.address, address, sizeof(unlock_dust_deposit_return.address));
    unlock_dust_deposit_return.amount = tx_amount_obj->valueint;

    // add address unlock to array
    utarray_push_back(unlock_conditions, &unlock_dust_deposit_return);
    return 0;
  }

  return -1;
}

static int deser_unlock_conditions(cJSON *output_obj, UT_array *unlock_conditions) {
  /*
  "unlockConditions": [],
  */
  cJSON *tx_unlock_conditions_obj = cJSON_GetObjectItemCaseSensitive(output_obj, JSON_KEY_UNLOCK_CONDITIONS);

  if (cJSON_IsArray(tx_unlock_conditions_obj)) {
    cJSON *elm = NULL;
    cJSON_ArrayForEach(elm, tx_unlock_conditions_obj) {
      cJSON *tx_unlock_condition_type_obj = cJSON_GetObjectItemCaseSensitive(elm, JSON_KEY_TYPE);
      if (cJSON_IsNumber(tx_unlock_condition_type_obj)) {
        switch (tx_unlock_condition_type_obj->valueint) {
          case UNLOCK_CONDITION_ADDRESS:
            if (deser_address_unlock(elm, unlock_conditions) != 0) {
              printf("[%s:%d] parsing address unlock failed\n", __func__, __LINE__);
              return -1;
            }
            break;
          case UNLOCK_CONDITION_DUST_DEPOSIT_RETURN:
            break;
          case UNLOCK_CONDITION_TIMELOCK:
            break;
          case UNLOCK_CONDITION_EXPIRATION:
            break;
          case UNLOCK_CONDITION_STATE_CONTROLLER_ADDRESS:
            break;
          case UNLOCK_CONDITION_GOVERNOR_ADDRESS:
            break;
          default:
            break;
        }
      }
    }
  } else {
    printf("[%s:%d]: %s is not an array object\n", __func__, __LINE__, JSON_KEY_UNLOCK_CONDITIONS);
    return -1;
  }

  return 0;
}

static int deser_feat_blocks(cJSON *output_obj, UT_array *feat_blocks) { return 0; }

int deser_message_tx_extended_output(cJSON *output_obj, payload_tx_t *payload_tx) {
  if (output_obj == NULL || payload_tx == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  /*
  "outputs": [
    { "type": 3,
      "amount": 10000000,
      "nativeTokens": [],
      "unlockConditions": [],
      "blocks": [] }
  ],
  */

  int ret = -1;
  tx_extended_output_t output = {};

  cJSON *tx_amount_obj = cJSON_GetObjectItemCaseSensitive(output_obj, JSON_KEY_AMOUNT);
  if (tx_amount_obj && cJSON_IsNumber(tx_amount_obj)) {
    output.amount = (uint64_t)tx_amount_obj->valuedouble;
  } else {
    printf("[%s:%d] parsing %s failed\n", __func__, __LINE__, JSON_KEY_AMOUNT);
    goto end;
  }

  cJSON *nativeTokens_obj = cJSON_GetObjectItemCaseSensitive(output_obj, JSON_KEY_NATIVE_TOKENS);
  if (!cJSON_IsArray(nativeTokens_obj) || (deser_native_tokens(nativeTokens_obj, output.nativeTokens) != 0)) {
    printf("[%s:%d]: parsing %s object failed \n", __func__, __LINE__, JSON_KEY_NATIVE_TOKENS);
    goto end;
  }

  cJSON *unlock_conditions_obj = cJSON_GetObjectItemCaseSensitive(output_obj, JSON_KEY_UNLOCK_CONDITIONS);
  if (!cJSON_IsArray(unlock_conditions_obj) ||
      (deser_unlock_conditions(unlock_conditions_obj, output.unlockConds) != 0)) {
    printf("[%s:%d]: parsing %s object failed \n", __func__, __LINE__, JSON_KEY_UNLOCK_CONDITIONS);
    goto end;
  }

  cJSON *feature_blocks_obj = cJSON_GetObjectItemCaseSensitive(output_obj, JSON_KEY_FEAT_BLOCKS);
  if (!cJSON_IsArray(feature_blocks_obj) || (deser_feat_blocks(feature_blocks_obj, output.featBlocks) != 0)) {
    printf("[%s:%d]: parsing %s object failed \n", __func__, __LINE__, JSON_KEY_FEAT_BLOCKS);
    goto end;
  }

  // add the output element to payload
  utarray_push_back(payload_tx->outputs, &output);

end:
  return ret;
}

int deser_message_tx_alias_output(cJSON *output_obj, payload_tx_t *payload_tx) { return 0; }

int deser_message_tx_foundry_output(cJSON *output_obj, payload_tx_t *payload_tx) { return 0; }

int deser_message_tx_nft_output(cJSON *output_obj, payload_tx_t *payload_tx) { return 0; }
