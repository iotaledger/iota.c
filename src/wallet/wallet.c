// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "client/api/restful/get_node_info.h"
#include "core/utils/slip10.h"
#include "wallet/bip39.h"
#include "wallet/wallet.h"

// max length of m/44'/4218'/Account'/Change'
#define IOTA_ACCOUNT_PATH_MAX 128

// TODO: unused function at the moment
#if 0
// validate path: m/44',/4218',/Account',/Change'
static int validate_pib44_path(char const path[]) {
  static char const* const iota_bip44_prefix = "m/44'/4218'";
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
    // unsigned long value = strtoul(token, &ptr, 10);

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
#endif

/**
 * @brief Get the address path
 *
 * @param[in] account The account index
 * @param[in] change change index which is {0, 1}, also known as wallet chain.
 * @param[in] index Address index
 * @param[in] buf The buffer holds BIP44 path
 * @param[in] buf_len the length of the buffer
 */
static void get_address_path(uint32_t account, bool change, uint32_t index, char* buf, size_t buf_len) {
  int ret_size = 0;
  // IOTA BIP44 Paths: m/44'/4128'/Account'/Change'/Index'
  // https://github.com/satoshilabs/slips/blob/master/slip-0044.md
  ret_size = snprintf(buf, buf_len, "m/44'/4218'/%" PRIu32 "'/%d'/%" PRIu32 "'", account, change, index);
  if ((size_t)ret_size >= buf_len) {
    buf[buf_len - 1] = '\0';
    printf("[%s:%d] path is truncated\n", __func__, __LINE__);
  }
}

#if 0  // TODO, remove or refactor?
static transaction_payload_t* wallet_build_transaction(iota_wallet_t* w, bool change, uint32_t sender_index,
                                                       byte_t receiver[], uint64_t balance, char const index[],
                                                       byte_t data[], size_t data_len) {
  char tmp_addr[IOTA_ADDRESS_HEX_BYTES + 1] = {};
  char addr_path[IOTA_ACCOUNT_PATH_MAX] = {};
  byte_t send_addr[ED25519_ADDRESS_BYTES] = {};
  byte_t tmp_tx_id[TRANSACTION_ID_BYTES] = {};
  ed25519_keypair_t addr_keypair = {};
  res_outputs_id_t* outputs_res = NULL;
  transaction_payload_t* tx_payload = NULL;
  int ret = -1;

  // TODO loop over start and end addresses
  // get address keypair and address
  get_address_path(w->account_index, change, sender_index, addr_path, sizeof(addr_path));

  if (address_keypair_from_path(w->seed, sizeof(w->seed), addr_path, &addr_keypair) != 0) {
    printf("[%s:%d] Cannot get address keypair\n", __func__, __LINE__);
    goto done;
  }

  if (address_from_ed25519_pub(addr_keypair.pub, send_addr) != 0) {
    printf("[%s:%d] Cannot get sending address \n", __func__, __LINE__);
    goto done;
  }

  // get outputs
  bin_2_hex(send_addr, sizeof(send_addr), tmp_addr, sizeof(tmp_addr));
  if (!(outputs_res = res_outputs_new())) {
    printf("[%s:%d] Err: invalid length of path\n", __func__, __LINE__);
    return NULL;
  }

  // FIXME : get_outputs_id method now accepts query params list
  if (get_outputs_id(&w->endpoint, false, tmp_addr, outputs_res) != 0) {
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

  size_t out_counts = res_outputs_output_id_count(outputs_res);
  // get outputs and tx id and tx output index from genesis
  uint64_t total_balance = 0;
  for (size_t i = 0; i < out_counts; i++) {
    char* output_id = res_outputs_output_id(outputs_res, i);
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
        if (total_balance >= balance) {
          // balance is sufficient from current inputs
          break;
        }
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
  res_outputs_free(outputs_res);

  if (ret == -1) {
    tx_payload_free(tx_payload);
    tx_payload = NULL;
    printf("[%s:%d] Err: build tx failed\n", __func__, __LINE__);
  }
  return tx_payload;
}
#endif

iota_wallet_t* wallet_create(char const ms[], char const pwd[], uint32_t account_index) {
  char mnemonic_tmp[512] = {};  // buffer for random mnemonic

  if (!pwd) {
    printf("passphrase is needed\n");
    return NULL;
  }

  iota_wallet_t* w = malloc(sizeof(iota_wallet_t));
  if (w) {
    strcpy(w->bech32HRP, NODE_DEFAULT_HRP);
    strcpy(w->endpoint.host, NODE_DEFAULT_HOST);
    w->endpoint.port = NODE_DEFAULT_PORT;
    w->endpoint.use_tls = true;
    w->account_index = account_index;

    // drive mnemonic seed from the given sentence and password
    if (ms) {
      // validating mnemonic sentence
      if (mnemonic_validation(ms, MS_LAN_EN)) {
        // create a new seed with pwd
        if (mnemonic_to_seed(ms, pwd, w->seed, sizeof(w->seed)) != 0) {
          printf("[%s:%d] derive mnemonic seed failed\n", __func__, __LINE__);
        } else {
          return w;
        }
      } else {
        printf("[%s:%d] invalid mnemonic sentence\n", __func__, __LINE__);
      }
    } else {
      // generator random ms
      if (mnemonic_generator(MS_ENTROPY_256, MS_LAN_EN, mnemonic_tmp, sizeof(mnemonic_tmp)) != 0) {
        printf("[%s:%d] genrating mnemonic failed\n", __func__, __LINE__);
      }
      if (mnemonic_to_seed(mnemonic_tmp, pwd, w->seed, sizeof(w->seed)) != 0) {
        printf("[%s:%d] derive mnemonic seed failed\n", __func__, __LINE__);
      } else {
        return w;
      }
    }
  }

  if (w) {
    free(w);
  }
  printf("allocate wallet object failed\n");
  return NULL;
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

int wallet_ed25519_address_from_index(iota_wallet_t* w, bool change, uint32_t index, address_t* out) {
  char bip_path_buf[IOTA_ACCOUNT_PATH_MAX] = {};

  if (!w || !out) {
    printf("[%s:%d] Err: invalid paramters\n", __func__, __LINE__);
    return -1;
  }

  // derive ed25519 address from seed and path
  get_address_path(w->account_index, change, index, bip_path_buf, sizeof(bip_path_buf));
  return ed25519_address_from_path(w->seed, sizeof(w->seed), bip_path_buf, out);
}

int wallet_balance_by_address(iota_wallet_t* w, address_t* addr, uint64_t* balance) {
  (void)w;
  (void)addr;
  (void)balance;
#if 0  // TODO, refactor
  char hex_addr[IOTA_ADDRESS_HEX_BYTES + 1] = {};
  res_balance_t* bal_res = NULL;

  // binary address to hex string
  if (bin_2_hex(addr, ED25519_ADDRESS_BYTES, hex_addr, sizeof(hex_addr))) {
    printf("[%s:%d] Err: Convert ed25519 address to hex string failed\n", __func__, __LINE__);
    return -1;
  }

  if ((bal_res = res_balance_new()) == NULL) {
    printf("[%s:%d] Err: OOM\n", __func__, __LINE__);
    return -1;
  }

  if (get_balance(&w->endpoint, false, hex_addr, bal_res) != 0) {
    printf("[%s:%d] Err: get balance API failed\n", __func__, __LINE__);
    res_balance_free(bal_res);
    return -1;
  }

  if (bal_res->is_error) {
    printf("[%s:%d] Err response: %s\n", __func__, __LINE__, bal_res->u.error->msg);
  } else {
    *balance = bal_res->u.output_balance->balance;
  }

  res_balance_free(bal_res);
  return 0;
#endif
  return -1;
}

int wallet_balance_by_bech32(iota_wallet_t* w, char const bech32[], uint64_t* balance) {
  // TODO
  (void)w;
  (void)bech32;
  (void)balance;
  return -1;
}

int wallet_unlock_outputs(iota_wallet_t* w, bool change, uint32_t index) {
  // TODO
  (void)w;
  (void)change;
  (void)index;
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
    printf("[%s:%d] allocate info response failed\n", __func__, __LINE__);
    return -1;
  }

  int ret = get_node_info(&w->endpoint, info);
  if (ret == 0) {
    if (info->is_error == false) {
      strncpy(w->bech32HRP, info->u.output_node_info->bech32hrp, sizeof(w->bech32HRP));
    } else {
      ret = -2;
      printf("[%s:%d] Error response: %s\n", __func__, __LINE__, info->u.error->msg);
    }
  }
  res_node_info_free(info);
  return ret;
}
