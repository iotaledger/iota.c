// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "client/api/restful/get_node_info.h"
#include "client/api/restful/get_outputs_id.h"
#include "core/models/outputs/output_basic.h"
#include "core/models/outputs/storage_deposit.h"
#include "wallet/bip39.h"
#include "wallet/output_basic.h"
#include "wallet/wallet.h"

#define NODE_DEFAULT_HRP "iota"
#define NODE_DEFAULT_HOST "chrysalis-nodes.iota.org"
#define NODE_DEFAULT_PORT 443

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

iota_wallet_t* wallet_create(char const ms[], char const pwd[], uint32_t coin_type, uint32_t account_index) {
  if (pwd == NULL) {
    printf("[%s:%d] passphrase is needed\n", __func__, __LINE__);
    return NULL;
  }

  iota_wallet_t* w = malloc(sizeof(iota_wallet_t));
  if (w) {
    strcpy(w->bech32HRP, NODE_DEFAULT_HRP);
    strcpy(w->endpoint.host, NODE_DEFAULT_HOST);
    w->endpoint.port = NODE_DEFAULT_PORT;
    w->endpoint.use_tls = true;
    w->account_index = account_index;
    w->coin_type = coin_type;

    // derive mnemonic seed from a given sentence and password
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
      char mnemonic_tmp[512] = {0};  // buffer for random mnemonic

      // generator random ms
      if (mnemonic_generator(MS_ENTROPY_256, MS_LAN_EN, mnemonic_tmp, sizeof(mnemonic_tmp)) != 0) {
        printf("[%s:%d] generating mnemonic failed\n", __func__, __LINE__);
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

void wallet_destroy(iota_wallet_t* w) {
  if (w) {
    free(w);
  }
}

int wallet_set_endpoint(iota_wallet_t* w, char const host[], uint16_t port, bool use_tls) {
  if (w == NULL || host == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  if (strlen(host) >= sizeof(w->endpoint.host)) {
    printf("[%s:%d] a length of a hostname is too long\n", __func__, __LINE__);
    return -1;
  }

  snprintf(w->endpoint.host, sizeof(w->endpoint.host), "%s", host);
  w->endpoint.port = port;
  w->endpoint.use_tls = use_tls;

  return 0;
}

int wallet_update_node_config(iota_wallet_t* w) {
  if (w == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  res_node_info_t* info = res_node_info_new();
  if (!info) {
    printf("[%s:%d] allocate info response failed\n", __func__, __LINE__);
    return -1;
  }

  int ret = get_node_info(&w->endpoint, info);
  if (ret == 0) {
    if (info->is_error == false) {
      uint8_t network_id_hash[CRYPTO_BLAKE2B_256_HASH_BYTES] = {};
      // update bech32 HRP
      strncpy(w->bech32HRP, info->u.output_node_info->bech32hrp, sizeof(w->bech32HRP));
      // update network protocol version
      w->protocol_version = info->u.output_node_info->protocol_version;
      // update network ID
      ret = iota_blake2b_sum((const uint8_t*)info->u.output_node_info->network_name,
                             strlen(info->u.output_node_info->network_name), network_id_hash, sizeof(network_id_hash));

      if (ret == 0) {
        memcpy(&w->network_id, network_id_hash, sizeof(w->network_id));
      } else {
        printf("[%s:%d] update network ID failed\n", __func__, __LINE__);
      }

      // update byte cost
      byte_cost_config_set(&w->byte_cost, info->u.output_node_info->rent_structure.v_byte_cost,
                           info->u.output_node_info->rent_structure.v_byte_factor_data,
                           info->u.output_node_info->rent_structure.v_byte_factor_key);

      // update indexer path
      size_t len = utarray_len(info->u.output_node_info->plugins);
      for (size_t i = 0; i < len; i++) {
        char** p = (char**)utarray_eltptr(info->u.output_node_info->plugins, i);
        // indexer path contains "indexer" string
        if (strstr(*p, "indexer")) {
          w->indexer_path[0] = '/';
          memcpy(&w->indexer_path[1], *p, strlen(*p) + 1);
        }
      }

    } else {
      ret = -2;
      printf("[%s:%d] Error response: %s\n", __func__, __LINE__, info->u.error->msg);
    }
  }

  res_node_info_free(info);

  return ret;
}

int wallet_get_address_path(iota_wallet_t* w, bool change, uint32_t index, char* buf, size_t buf_len) {
  if (w == NULL || buf == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  int ret_size = snprintf(buf, buf_len, "m/44'/%" PRIu32 "'/%" PRIu32 "'/%d'/%" PRIu32 "'", w->coin_type,
                          w->account_index, change, index);
  if ((size_t)ret_size >= buf_len) {
    buf[buf_len - 1] = '\0';
    printf("[%s:%d] path is truncated\n", __func__, __LINE__);
  }

  return 0;
}

int wallet_ed25519_address_from_index(iota_wallet_t* w, bool change, uint32_t index, address_t* addr) {
  if (w == NULL || addr == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  char bip_path_buf[IOTA_ACCOUNT_PATH_MAX] = {0};

  // derive ed25519 address from seed and path
  if (wallet_get_address_path(w, change, index, bip_path_buf, sizeof(bip_path_buf)) != 0) {
    printf("[%s:%d] can not derive ed25519 address from seed and path\n", __func__, __LINE__);
    return -1;
  }

  return ed25519_address_from_path(w->seed, sizeof(w->seed), bip_path_buf, addr);
}

int wallet_get_address_and_keypair_from_index(iota_wallet_t* w, bool change, uint32_t index, address_t* addr,
                                              ed25519_keypair_t* keypair) {
  char addr_path[IOTA_ACCOUNT_PATH_MAX] = {};

  if (wallet_ed25519_address_from_index(w, change, index, addr) != 0) {
    printf("[%s:%d] get sender address failed\n", __func__, __LINE__);
    return -1;
  }

  if (wallet_get_address_path(w, change, index, addr_path, sizeof(addr_path)) != 0) {
    printf("[%s:%d] can not derive address path from seed and path\n", __func__, __LINE__);
    return -1;
  }

  if (address_keypair_from_path(w->seed, sizeof(w->seed), addr_path, keypair) != 0) {
    printf("[%s:%d] get address keypair failed\n", __func__, __LINE__);
    return -1;
  }

  return 0;
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

bool wallet_is_collected_balance_sufficient(iota_wallet_t* w, uint64_t send_amount, uint64_t collected_amount,
                                            uint64_t remainder_amount, native_tokens_list_t* send_native_tokens,
                                            native_tokens_list_t* collected_native_tokens,
                                            native_tokens_list_t* remainder_native_tokens) {
  if (w == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return false;
  }

  if (collected_amount < send_amount) {
    return false;
  }

  native_tokens_list_t* elm;
  LL_FOREACH(send_native_tokens, elm) {
    native_token_t* token = native_tokens_find_by_id(collected_native_tokens, elm->token->token_id);
    if (token) {
      if (uint256_equal(&token->amount, &elm->token->amount) < 0) {
        return false;
      }
    } else {
      return false;
    }
  }

  // if remainder is needed, check if there is enough base tokens for its minimum storage protection
  if (remainder_amount > 0 || native_tokens_count(remainder_native_tokens) > 0) {
    // create Basic Output with address unlock condition
    address_t remainder_addr = {0};
    output_basic_t* remainder_output =
        wallet_output_basic_create(&remainder_addr, remainder_amount, remainder_native_tokens);
    if (!remainder_output) {
      printf("[%s:%d] can not create a reminder basic output\n", __func__, __LINE__);
      return false;
    }

    // calculate minimum storage deposit for remainder output
    uint64_t min_storage_deposit = calc_minimum_output_deposit(&w->byte_cost, OUTPUT_BASIC, remainder_output);
    if (remainder_amount < min_storage_deposit) {
      output_basic_free(remainder_output);
      return false;
    }
    output_basic_free(remainder_output);
  }

  return true;
}

int wallet_calculate_remainder_amount(uint64_t send_amount, uint64_t collected_amount,
                                      native_tokens_list_t* send_native_tokens,
                                      native_tokens_list_t* collected_native_tokens, uint64_t* remainder_amount,
                                      native_tokens_list_t** remainder_native_tokens) {
  if (remainder_amount == NULL || *remainder_native_tokens != NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // calculate remainder for base token
  *remainder_amount = collected_amount - send_amount;

  // calculate remainder for native tokens
  *remainder_native_tokens = native_tokens_new();
  native_tokens_list_t* elm;
  LL_FOREACH(collected_native_tokens, elm) {
    native_token_t* token = native_tokens_find_by_id(send_native_tokens, elm->token->token_id);
    if (token) {
      uint256_t* remainder = malloc(sizeof(uint256_t));
      if (!remainder) {
        printf("[%s:%d] OOM\n", __func__, __LINE__);
        native_tokens_free(*remainder_native_tokens);
        return -1;
      }
      if (uint256_sub(remainder, &elm->token->amount, &token->amount) != true) {
        printf("[%s:%d] can not substitute amount of two native tokens\n", __func__, __LINE__);
        native_tokens_free(*remainder_native_tokens);
        uint256_free(remainder);
        return -1;
      }
      if (native_tokens_add(remainder_native_tokens, elm->token->token_id, remainder) != 0) {
        printf("[%s:%d] can not add native token to a list\n", __func__, __LINE__);
        native_tokens_free(*remainder_native_tokens);
        uint256_free(remainder);
        return -1;
      }
      uint256_free(remainder);
    } else {
      // native token is not in send_native_tokens, but it's in one of collected unspent outputs, so it must be sent
      // back to sender
      if (native_tokens_add(remainder_native_tokens, elm->token->token_id, &elm->token->amount) != 0) {
        printf("[%s:%d] can not add native token to a list\n", __func__, __LINE__);
        native_tokens_free(*remainder_native_tokens);
        return -1;
      }
    }
  }

  return 0;
}

core_block_t* wallet_create_core_block(iota_wallet_t* w, transaction_payload_t* tx,
                                       utxo_outputs_list_t* unspent_outputs, signing_data_list_t* sign_data) {
  if (w == NULL || tx == NULL || unspent_outputs == NULL || sign_data == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  // create a core block
  core_block_t* core_block = core_block_new(w->protocol_version);
  if (!core_block) {
    printf("[%s:%d] create core block failed\n", __func__, __LINE__);
    return NULL;
  }
  core_block->payload_type = CORE_BLOCK_PAYLOAD_TRANSACTION;
  core_block->payload = tx;

  // calculate inputs commitment
  if (tx_essence_inputs_commitment_calculate(tx->essence, unspent_outputs) != 0) {
    printf("[%s:%d] calculate inputs commitment failed\n", __func__, __LINE__);
    core_block_free(core_block);
    return NULL;
  }

  // calculate transaction essence hash
  byte_t essence_hash[CRYPTO_BLAKE2B_256_HASH_BYTES] = {};
  if (core_block_essence_hash_calc(core_block, essence_hash, sizeof(essence_hash)) != 0) {
    printf("[%s:%d] calculate essence hash failed\n", __func__, __LINE__);
    core_block_free(core_block);
    return NULL;
  }

  // sign transaction
  if (signing_transaction_sign(essence_hash, sizeof(essence_hash), tx->essence->inputs, sign_data, &tx->unlocks) != 0) {
    printf("[%s:%d] sign transaction failed\n", __func__, __LINE__);
    core_block_free(core_block);
    return NULL;
  }

  // syntactic validation
  if (tx_payload_syntactic(tx, &w->byte_cost) != true) {
    printf("[%s:%d] invalid transaction payload\n", __func__, __LINE__);
    core_block_free(core_block);
    return NULL;
  }

  return core_block;
}

int wallet_send_block(iota_wallet_t* w, core_block_t* core_block, res_send_block_t* blk_res) {
  if (w == NULL || core_block == NULL || blk_res == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // send block to a network
  if (send_core_block(&w->endpoint, core_block, blk_res) != 0) {
    printf("[%s:%d] failed to send a block to a network\n", __func__, __LINE__);
    return -1;
  }

  return 0;
}
