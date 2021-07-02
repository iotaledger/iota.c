// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "client/api/v1/get_balance.h"
#include "client/api/v1/get_node_info.h"
#include "client/api/v1/get_output.h"
#include "client/api/v1/get_outputs_from_address.h"
#include "client/api/v1/send_message.h"
#include "core/models/message.h"
#include "core/utils/byte_buffer.h"
#include "wallet/wallet.h"

// TODO: move to utils?
// validate path: m/44',/4128',/Account',/Change'
static int validate_pib44_path(char const path[]) {
  int ret = -1;
  char tmp_path[IOTA_ACCOUNT_PATH_MAX] = {};
  size_t path_len = strlen(path);
  if (path_len > IOTA_ACCOUNT_PATH_MAX - 1 || path_len == 0 || path_len == strlen(iota_bip44_prefix)) {
    printf("[%s:%d] Err: invalid length of path\n", __func__, __LINE__);
    return ret;
  }

  if (memcmp(iota_bip44_prefix, path, strlen(iota_bip44_prefix)) != 0) {
    printf("[%s:%d] Err: invalid path prefix\n", __func__, __LINE__);
    return ret;
  }

  if (strstr(path, "//") != NULL || strstr(path, "''") != NULL || strstr(path, "'H") != NULL ||
      strstr(path, "H'") != NULL || strstr(path, "HH") != NULL || strstr(path, "h") != NULL) {
    printf("[%s:%d] Err: invalid path format\n", __func__, __LINE__);
    return ret;
  }

  memcpy(tmp_path, path + strlen(iota_bip44_prefix) + 1, path_len - (strlen(iota_bip44_prefix) + 1));
  char* token = strtok(tmp_path, "/");
  size_t token_count = 0;
  while (token != NULL) {
    char* ptr = NULL;
    // check token format
    if (strncmp(token, "\'", 1) == 0 || strncmp(token, "H", 1) == 0) {
      // invalid format
      printf("[%s:%d] invalid path format\n", __func__, __LINE__);
      break;
    }

    // get value
    unsigned long value = strtoul(token, &ptr, 10);

    // hardened
    if (!(strncmp(ptr, "\'", 1) == 0 || strncmp(ptr, "H", 1) == 0)) {
      // invalid format
      printf("[%s:%d] Err: invalid path format: hardened is needed\n", __func__, __LINE__);
      break;
    }
    // gets next token
    token = strtok(NULL, "/");
    token_count++;
  }

  if (token_count != 2) {
    printf("[%s:%d] Err: path format is m/44'/4218'/Account'/Change'\n", __func__, __LINE__);
  } else {
    ret = 0;
  }
  return ret;
}

// get path from address
static void wallet_path_from_index(iota_wallet_t* w, uint32_t index, char* buf, size_t buf_len) {
  int ret_size = 0;
  // Bip44 Paths: m/44'/4128'/Account'/Change'/Index'
  ret_size = snprintf(buf, buf_len, "%s/%" PRIu32 "'", w->account, index);
  if (ret_size >= buf_len) {
    buf[buf_len - 1] = '\0';
  }
}

static transaction_payload_t* wallet_build_transaction(iota_wallet_t* w, uint32_t sender, byte_t receiver[],
                                                       uint64_t balance, char const index[], byte_t data[],
                                                       size_t data_len) {
  char tmp_addr[IOTA_ADDRESS_HEX_BYTES + 1] = {};
  char addr_path[IOTA_ACCOUNT_PATH_MAX] = {};
  byte_t send_addr[ED25519_ADDRESS_BYTES] = {};
  byte_t tmp_tx_id[TRANSACTION_ID_BYTES] = {};
  iota_keypair_t addr_keypair = {};
  res_outputs_address_t* outputs_res = NULL;
  transaction_payload_t* tx_payload = NULL;
  int ret = -1;

  // TODO loop over start and end addresses
  // get address keypair and address
  wallet_path_from_index(w, sender, addr_path, IOTA_ACCOUNT_PATH_MAX);

  if (address_keypair_from_path(w->seed, addr_path, &addr_keypair) != 0) {
    printf("[%s:%d] Cannot get address keypair\n", __func__, __LINE__);
    goto done;
  }

  if (address_from_ed25519_pub(addr_keypair.pub, send_addr) != 0) {
    printf("[%s:%d] Cannot get sending address \n", __func__, __LINE__);
    goto done;
  }

  // get outputs
  bin_2_hex(send_addr, sizeof(send_addr), tmp_addr, sizeof(tmp_addr));
  if (!(outputs_res = res_outputs_address_new())) {
    printf("[%s:%d] Err: invalid length of path\n", __func__, __LINE__);
    return NULL;
  }

  if (get_outputs_from_address(&w->endpoint, tmp_addr, outputs_res) != 0) {
    printf("[%s:%d] Err: get outputs from address failed\n", __func__, __LINE__);
    goto done;
  }

  if (outputs_res->is_error) {
    printf("[%s:%d] Error get outputs from addr: %s\n", __func__, __LINE__, outputs_res->u.error->msg);
    goto done;
  }

  if ((tx_payload = tx_payload_new()) == NULL) {
    printf("[%s:%d] allocate tx payload failed\n", __func__, __LINE__);
    goto done;
  }

  size_t out_counts = res_outputs_address_output_id_count(outputs_res);
  // get outputs and tx id and tx output index from genesis
  uint64_t total_balance = 0;
  for (size_t i = 0; i < out_counts; i++) {
    char* output_id = res_outputs_address_output_id(outputs_res, i);
    res_output_t out_id_res = {};
    ret = get_output(&w->endpoint, output_id, &out_id_res);
    if (out_id_res.is_error) {
      printf("[%s:%d] Error response: %s\n", __func__, __LINE__, out_id_res.u.error->msg);
      res_err_free(out_id_res.u.error);
    }

    // add input to transaction essence
    if (!out_id_res.u.output.is_spent) {
      if (out_id_res.u.output.address_type == ADDRESS_VER_ED25519) {
        hex_2_bin(out_id_res.u.output.tx_id, TRANSACTION_ID_BYTES * 2, tmp_tx_id, sizeof(tmp_tx_id));
        ret = tx_payload_add_input_with_key(tx_payload, tmp_tx_id, out_id_res.u.output.output_idx, addr_keypair.pub,
                                            addr_keypair.priv);
        total_balance += out_id_res.u.output.amount;
      } else {
        printf("Unknow address type\n");
      }
    }
  }

  if (utxo_inputs_count(&tx_payload->essence->inputs) == 0) {
    printf("[%s:%d] Err: input not found\n", __func__, __LINE__);
    ret = -1;
    goto done;
  }

  if (total_balance < balance) {
    printf("[%s:%d] Err: balance is not sufficient, total:%" PRIu64 " send balance:%" PRIu64 "\n", __func__, __LINE__,
           total_balance, balance);
    ret = -1;
    goto done;
  }

  uint64_t remainder = total_balance - balance;
  if (remainder > 0) {
    ret = tx_payload_add_output(tx_payload, OUTPUT_SINGLE_OUTPUT, receiver, balance);
    ret = tx_payload_add_output(tx_payload, OUTPUT_SINGLE_OUTPUT, send_addr, total_balance - balance);
  } else {
    ret = tx_payload_add_output(tx_payload, OUTPUT_SINGLE_OUTPUT, receiver, balance);
  }

  // with indexation?
  if (index && data && data_len != 0) {
    ret = tx_essence_add_payload(tx_payload->essence, 2, (void*)indexation_create(index, data, data_len));
  }

done:
  res_outputs_address_free(outputs_res);

  if (ret == -1) {
    tx_payload_free(tx_payload);
    tx_payload = NULL;
    printf("[%s:%d] Err: build tx failed\n", __func__, __LINE__);
  }
  return tx_payload;
}

iota_wallet_t* wallet_create(byte_t const seed[], char const path[]) {
  if (!seed || !path) {
    printf("[%s:%d] Err: invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  if (validate_pib44_path(path)) {
    return NULL;
  }

  iota_wallet_t* w = malloc(sizeof(iota_wallet_t));
  if (w) {
    memset(w->bech32HRP, 0, sizeof(w->bech32HRP));
    memcpy(w->seed, seed, IOTA_SEED_BYTES);
    memcpy(w->account, path, strlen(path) + 1);
    strcpy(w->endpoint.host, NODE_DEFAULT_HOST);
    w->endpoint.port = NODE_DEFAULT_PORT;
    w->endpoint.use_tls = false;
  }
  return w;
}

int wallet_set_endpoint(iota_wallet_t* w, char const host[], uint16_t port, bool use_tls) {
  if (!w || !host) {
    printf("[%s:%d] Err: invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  if (strlen(host) >= sizeof(w->endpoint.host)) {
    printf("[%s:%d] Err: The length of hostname is too long\n", __func__, __LINE__);
    return -1;
  }

  snprintf(w->endpoint.host, sizeof(w->endpoint.host), "%s", host);
  w->endpoint.port = port;
  w->endpoint.use_tls = use_tls;
  return 0;
}

int wallet_address_by_index(iota_wallet_t* w, uint32_t index, byte_t addr[]) {
  char path_buf[IOTA_ACCOUNT_PATH_MAX] = {};

  if (!w || !addr) {
    printf("[%s:%d] Err: invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  wallet_path_from_index(w, index, path_buf, IOTA_ACCOUNT_PATH_MAX);
  return address_from_path(w->seed, path_buf, addr);
}

int wallet_balance_by_address(iota_wallet_t* w, byte_t const addr[], uint64_t* balance) {
  char hex_addr[IOTA_ADDRESS_HEX_BYTES + 1] = {};
  res_balance_t* bal_res = NULL;

  // binary address to hex string
  if (bin_2_hex(addr, ED25519_ADDRESS_BYTES, hex_addr, sizeof(hex_addr))) {
    printf("[%s:%d] Err: Convert binary address to hex string failed\n", __func__, __LINE__);
    return -1;
  }

  if ((bal_res = res_balance_new()) == NULL) {
    printf("[%s:%d] Err: OOM\n", __func__, __LINE__);
    return -1;
  }

  if (get_balance(&w->endpoint, hex_addr, bal_res) != 0) {
    printf("[%s:%d] Err: ge balance API failed\n", __func__, __LINE__);
    res_balance_free(bal_res);
    return -1;
  }

  if (bal_res->is_error) {
    printf("Err response: %s\n", bal_res->u.error->msg);
  } else {
    *balance = bal_res->u.output_balance->balance;
  }

  res_balance_free(bal_res);
  return 0;
}

int wallet_balance_by_index(iota_wallet_t* w, uint32_t index, uint64_t* balance) {
  byte_t addr[ED25519_ADDRESS_BYTES] = {};
  int ret = wallet_address_by_index(w, index, addr);
  if (ret == 0) {
    ret = wallet_balance_by_address(w, addr, balance);
  }
  return ret;
}

int wallet_send(iota_wallet_t* w, uint32_t sender_index, byte_t receiver[], uint64_t balance, char const index[],
                byte_t data[], size_t data_len, char msg_id[], size_t msg_id_len) {
  core_message_t* msg = NULL;
  indexation_t* idx = NULL;
  transaction_payload_t* tx = NULL;
  res_send_message_t msg_res = {};

  if (!w) {
    printf("[%s:%d] Err: invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  if (msg_id_len < IOTA_MESSAGE_ID_HEX_BYTES + 1) {
    printf("[%s:%d] Err: msg_id buffer is too small\n", __func__, __LINE__);
    return -1;
  }

  // build payload
  if (!receiver || balance == 0) {
    if (!index || !data) {
      printf("[%s:%d] Err: index and data parameters are needed\n", __func__, __LINE__);
      return -1;
    }
    if ((idx = indexation_create(index, data, data_len)) == NULL) {
      printf("[%s:%d] Err: create indexation payload failed\n", __func__, __LINE__);
      return -1;
    }
  } else {
    // transaction
    if ((tx = wallet_build_transaction(w, sender_index, receiver, balance, index, data, data_len)) == NULL) {
      printf("[%s:%d] Err: create transaction payload failed\n", __func__, __LINE__);
      return -1;
    }
  }

  // put payload into message
  if ((msg = core_message_new()) == NULL) {
    printf("[%s:%d] Err: create message failed\n", __func__, __LINE__);
    if (tx) {
      tx_payload_free(tx);
    } else {
      indexation_free(idx);
    }
    return -1;
  }

  if (!tx) {
    // indexation payload only
    msg->payload = idx;
    msg->payload_type = MSG_PAYLOAD_INDEXATION;
  } else {
    // transaction payload
    msg->payload = tx;
    msg->payload_type = MSG_PAYLOAD_TRANSACTION;
    if (core_message_sign_transaction(msg) != 0) {
      printf("[%s:%d] Err: sign transaction failed\n", __func__, __LINE__);
      core_message_free(msg);
      return -1;
    }
  }

  // send message
  if (send_core_message(&w->endpoint, msg, &msg_res) == 0) {
    strncpy(msg_id, msg_res.u.msg_id, msg_id_len);
    core_message_free(msg);
    return 0;
  } else {
    if (msg_res.is_error) {
      printf("[%s:%d] Error response: %s\n", __func__, __LINE__, msg_res.u.error->msg);
      res_err_free(msg_res.u.error);
    }
  }

  core_message_free(msg);
  return -1;
}

void wallet_destroy(iota_wallet_t* w) {
  if (w) {
    free(w);
  }
}

int wallet_update_bech32HRP(iota_wallet_t* w) {
  res_node_info_t* info = res_node_info_new();
  if (!info) {
    // OOM?
    return -1;
  }

  int ret = get_node_info(&w->endpoint, info);
  if (ret == 0) {
    if (info->is_error == false) {
      strncpy(w->bech32HRP, info->u.output_node_info->bech32hrp, sizeof(w->bech32HRP));
    } else {
      ret = -2;
      printf("Error: %s\n", info->u.error->msg);
    }
  }
  res_node_info_free(info);
  return ret;
}