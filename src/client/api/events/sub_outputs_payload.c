// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/events/sub_outputs_payload.h"
#include "client/api/json_parser/json_utils.h"
#include "core/address.h"
#include "core/models/outputs/output_foundry.h"
#include "core/utils/iota_str.h"
#include "core/utils/macros.h"

int event_sub_outputs_id(event_client_handle_t client, int *mid, char const output_id[], int qos) {
  if ((strlen(output_id)) != BIN_TO_HEX_BYTES(IOTA_OUTPUT_ID_BYTES)) {
    printf("[%s:%d]: Output Id length is invalid\n", __func__, __LINE__);
    return -1;
  }

  // Buffer enough for outputs/{outputId}
  char topic_buff[79] = {};
  sprintf(topic_buff, "outputs/0x%s", output_id);

  return event_subscribe(client, mid, topic_buff, qos);
}

int event_sub_outputs_unlock_address(event_client_handle_t client, int *mid, char const *const unlock_condition,
                                     char const *const addr_bech32, int qos) {
  // Check if addr_bech32 has minimum required length
  if (strlen(addr_bech32) < BIN_TO_HEX_STR_BYTES(ADDRESS_MIN_BYTES)) {
    printf("[%s:%d] invalid bech32 address\n", __func__, __LINE__);
    return -1;
  }
  // Check if unlock condition is present
  if (strlen(unlock_condition) > 0) {
    printf("[%s:%d] invalid unlock condition\n", __func__, __LINE__);
    return -1;
  }

  iota_str_t *topic_buff = NULL;
  char const *const topic_str = "outputs/unlock/";

  topic_buff =
      iota_str_reserve(strlen(topic_str) + strlen(unlock_condition) + BIN_TO_HEX_STR_BYTES(ADDRESS_MAX_BYTES) + 2);
  if (topic_buff == NULL) {
    printf("[%s:%d]: allocate command buffer failed\n", __func__, __LINE__);
    return -1;
  }

  // composing API command
  snprintf(topic_buff->buf, topic_buff->cap, "%s%s%s%s", topic_str, unlock_condition, "/", addr_bech32);
  topic_buff->len = strlen(topic_buff->buf);

  int ret = event_subscribe(client, mid, topic_buff->buf, qos);
  iota_str_destroy(topic_buff);
  return ret;
}

int event_sub_outputs_unlock_address_spent(event_client_handle_t client, int *mid, char const *const unlock_condition,
                                           char const *const addr_bech32, int qos) {
  // Check if addr_bech32 has minimum required length
  if (strlen(addr_bech32) < BIN_TO_HEX_STR_BYTES(ADDRESS_MIN_BYTES)) {
    printf("[%s:%d] invalid bech32 address\n", __func__, __LINE__);
    return -1;
  }
  // Check if unlock condition is present
  if (strlen(unlock_condition) > 0) {
    printf("[%s:%d] invalid unlock condition\n", __func__, __LINE__);
    return -1;
  }

  iota_str_t *topic_buff = NULL;
  char const *const topic_str = "outputs/unlock/";
  // outputs/unlock/{condition}/{address}/spent
  topic_buff =
      iota_str_reserve(strlen(topic_str) + strlen(unlock_condition) + BIN_TO_HEX_STR_BYTES(ADDRESS_MAX_BYTES) + 8);
  if (topic_buff == NULL) {
    printf("[%s:%d]: allocate command buffer failed\n", __func__, __LINE__);
    return -1;
  }

  // composing API command
  snprintf(topic_buff->buf, topic_buff->cap, "%s%s%s%s%s", topic_str, unlock_condition, "/", addr_bech32, "/spent");
  topic_buff->len = strlen(topic_buff->buf);

  int ret = event_subscribe(client, mid, topic_buff->buf, qos);
  iota_str_destroy(topic_buff);
  return ret;
}

int event_sub_outputs_alias_id(event_client_handle_t client, int *mid, char const alias_id[], int qos) {
  if (strlen(alias_id) != BIN_TO_HEX_BYTES(ALIAS_ID_BYTES)) {
    printf("[%s:%d] incorrect length of id\n", __func__, __LINE__);
    return -1;
  }

  // Buffer enough for outputs/aliases/{aliasId}
  char topic_buff[59] = {};
  sprintf(topic_buff, "outputs/aliases/0x%s", alias_id);

  return event_subscribe(client, mid, topic_buff, qos);
}

int event_sub_outputs_nft_id(event_client_handle_t client, int *mid, char const nft_id[], int qos) {
  if (strlen(nft_id) != BIN_TO_HEX_BYTES(NFT_ID_BYTES)) {
    printf("[%s:%d] incorrect length of id\n", __func__, __LINE__);
    return -1;
  }

  // Buffer enough for outputs/nfts/{nftId}
  char topic_buff[56] = {};
  sprintf(topic_buff, "outputs/nfts/0x%s", nft_id);

  return event_subscribe(client, mid, topic_buff, qos);
}

int event_sub_outputs_foundry_id(event_client_handle_t client, int *mid, char const foundry_id[], int qos) {
  if (strlen(foundry_id) != BIN_TO_HEX_BYTES(FOUNDRY_ID_BYTES)) {
    printf("[%s:%d] incorrect length of id\n", __func__, __LINE__);
    return -1;
  }

  // Buffer enough for outputs/foundries/{foundryId}
  char topic_buff[73] = {};
  sprintf(topic_buff, "outputs/foundries/0x%s", foundry_id);

  return event_subscribe(client, mid, topic_buff, qos);
}
