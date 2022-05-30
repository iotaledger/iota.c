// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "client/api/restful/get_node_info.h"
#include "client/api/restful/get_output.h"
#include "core/models/outputs/output_alias.h"
#include "core/models/outputs/output_basic.h"
#include "core/models/outputs/output_foundry.h"
#include "core/models/outputs/output_nft.h"
#include "core/models/outputs/storage_deposit.h"
#include "wallet/bip39.h"
#include "wallet/output_basic.h"
#include "wallet/wallet.h"

#define NODE_DEFAULT_HRP "iota"
#define NODE_DEFAULT_HOST "chrysalis-nodes.iota.org"
#define NODE_DEFAULT_PORT 443

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

static int create_signatures_for_inputs(utxo_outputs_list_t* inputs, ed25519_keypair_t* sender_key,
                                        signing_data_list_t** sign_data) {
  if (inputs == NULL || sender_key == NULL || *sign_data != NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  utxo_outputs_list_t* elm;
  LL_FOREACH(inputs, elm) {
    // add signing data (Basic output must have the address unlock condition)
    // get address unlock condition from the basic output
    unlock_cond_t* unlock_cond = NULL;

    switch (elm->output->output_type) {
      case OUTPUT_BASIC:
        unlock_cond =
            condition_list_get_type(((output_basic_t*)elm->output->output)->unlock_conditions, UNLOCK_COND_ADDRESS);
        break;
      case OUTPUT_ALIAS:
        unlock_cond =
            condition_list_get_type(((output_alias_t*)elm->output->output)->unlock_conditions, UNLOCK_COND_STATE);
        break;
      case OUTPUT_FOUNDRY:
        unlock_cond = condition_list_get_type(((output_foundry_t*)elm->output->output)->unlock_conditions,
                                              UNLOCK_COND_IMMUT_ALIAS);
        break;
      case OUTPUT_NFT:
        unlock_cond =
            condition_list_get_type(((output_nft_t*)elm->output->output)->unlock_conditions, UNLOCK_COND_ADDRESS);
        break;
      case OUTPUT_SINGLE_OUTPUT:
      case OUTPUT_DUST_ALLOWANCE:
      case OUTPUT_TREASURY:
      default:
        break;
    }

    if (!unlock_cond) {
      return -1;
    }

    // add address unlock condition into the signing data list
    if (signing_data_add(unlock_cond->obj, NULL, 0, sender_key, sign_data) != 0) {
      return -1;
    }
  }

  return 0;
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
      if (remainder->bits[0] > 0 || remainder->bits[1] > 0 || remainder->bits[2] > 0 || remainder->bits[3] > 0) {
        if (native_tokens_add(remainder_native_tokens, elm->token->token_id, remainder) != 0) {
          printf("[%s:%d] can not add native token to a list\n", __func__, __LINE__);
          native_tokens_free(*remainder_native_tokens);
          uint256_free(remainder);
          return -1;
        }
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

static bool is_unspent_basic_output_useful(iota_wallet_t* w, output_basic_t* output, uint64_t send_amount,
                                           uint64_t collected_amount, uint64_t remainder_amount,
                                           native_tokens_list_t* send_native_tokens,
                                           native_tokens_list_t* collected_native_tokens,
                                           native_tokens_list_t* remainder_native_tokens) {
  if (output == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  // use unspent output if collected amount is lower than amount needed to be sent
  if (collected_amount < send_amount && output->amount > 0) {
    return true;
  }

  // is there any useful native tokens inside unspent output
  native_tokens_list_t* elm;
  LL_FOREACH(output->native_tokens, elm) {
    native_token_t* send_native_token = native_tokens_find_by_id(send_native_tokens, elm->token->token_id);
    native_token_t* collected_native_token = native_tokens_find_by_id(collected_native_tokens, elm->token->token_id);

    if (send_native_token) {
      if (!collected_native_token) {
        return true;
      }
      if (collected_native_token && uint256_equal(&send_native_token->amount, &collected_native_token->amount) > 0) {
        return true;
      }
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
      return true;
    }
    output_basic_free(remainder_output);
  }

  return false;
}

static int update_collected_native_tokens(native_tokens_list_t* native_tokens,
                                          native_tokens_list_t** collected_native_tokens) {
  native_tokens_list_t* elm;
  LL_FOREACH(native_tokens, elm) {
    native_token_t* token = native_tokens_find_by_id(*collected_native_tokens, elm->token->token_id);
    if (token) {
      if (uint256_add(&token->amount, &token->amount, &elm->token->amount) != true) {
        printf("[%s:%d] can not add amount of two native tokens\n", __func__, __LINE__);
        return -1;
      }
    } else {
      if (native_tokens_add(collected_native_tokens, elm->token->token_id, &elm->token->amount) != 0) {
        printf("[%s:%d] can not add native token to a list\n", __func__, __LINE__);
        return -1;
      }
    }
  }

  return 0;
}

int wallet_get_unspent_outputs_and_create_remainder(iota_wallet_t* w, transaction_essence_t* essence,
                                                    address_t* sender_addr, utxo_inputs_list_t* inputs,
                                                    utxo_outputs_list_t* outputs, native_tokens_list_t* minted_tokens,
                                                    bool* balance_sufficient, utxo_outputs_list_t** unspent_outputs,
                                                    output_basic_t** remainder) {
  if (w == NULL || essence == NULL || sender_addr == NULL || outputs == NULL || *unspent_outputs != NULL ||
      *remainder != NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  *unspent_outputs = utxo_outputs_new();
  *balance_sufficient = false;

  uint64_t collected_amount = 0;
  native_tokens_list_t* collected_native_tokens = native_tokens_new();

  if (minted_tokens) {
    native_tokens_list_t* elm;
    LL_FOREACH(minted_tokens, elm) {
      native_tokens_add(&collected_native_tokens, elm->token->token_id, &elm->token->amount);
    }
  }

  utxo_inputs_list_t* input_elm;
  if (inputs) {
    LL_FOREACH(inputs, input_elm) {
      res_output_t* input_res = get_output_response_new();
      if (!input_res) {
        printf("[%s:%d] failed to create output response object\n", __func__, __LINE__);
        native_tokens_free(collected_native_tokens);
        return -1;
      }

      byte_t output_id[IOTA_OUTPUT_ID_BYTES];
      memcpy(output_id, input_elm->input->tx_id, IOTA_TRANSACTION_ID_BYTES);
      memcpy(output_id + IOTA_TRANSACTION_ID_BYTES, &input_elm->input->output_index, sizeof(uint16_t));

      char output_id_hex[BIN_TO_HEX_BYTES(IOTA_OUTPUT_ID_BYTES) + 1];
      bin_2_hex(output_id, sizeof(output_id), NULL, output_id_hex, sizeof(output_id_hex));

      if (get_output(&w->endpoint, output_id_hex, input_res) != 0) {
        printf("[%s:%d] failed to get unspent output from a node\n", __func__, __LINE__);
        native_tokens_free(collected_native_tokens);
        get_output_response_free(input_res);
        return -1;
      }

      if (input_res->is_error) {
        printf("[%s:%d] %s\n", __func__, __LINE__, input_res->u.error->msg);
        native_tokens_free(collected_native_tokens);
        get_output_response_free(input_res);
        return -1;
      }

      switch (input_res->u.data->output->output_type) {
        case OUTPUT_BASIC: {
          output_basic_t* output_basic = input_res->u.data->output->output;

          // update collected amount
          collected_amount += output_basic->amount;

          // update collected native tokens
          if (update_collected_native_tokens(output_basic->native_tokens, &collected_native_tokens) != 0) {
            printf("[%s:%d] failed to update collected native tokens list\n", __func__, __LINE__);
            native_tokens_free(collected_native_tokens);
            get_output_response_free(input_res);
            return -1;
          }

          // add unspent output into unspent outputs list
          if (utxo_outputs_add(unspent_outputs, OUTPUT_BASIC, output_basic) != 0) {
            printf("[%s:%d] can not add unspent output to unspent outputs list\n", __func__, __LINE__);
            native_tokens_free(collected_native_tokens);
            get_output_response_free(input_res);
            return -1;
          }

          // add unspent output into a transaction essence
          if (tx_essence_add_input(essence, 0, input_res->u.data->meta.tx_id, input_res->u.data->meta.output_index) !=
              0) {
            printf("[%s:%d] can not add unspent output to transaction essence\n", __func__, __LINE__);
            native_tokens_free(collected_native_tokens);
            get_output_response_free(input_res);
            return -1;
          }

          break;
        }
        case OUTPUT_ALIAS: {
          output_alias_t* output_alias = input_res->u.data->output->output;

          // update collected amount
          collected_amount += output_alias->amount;

          // update collected native tokens
          if (update_collected_native_tokens(output_alias->native_tokens, &collected_native_tokens) != 0) {
            printf("[%s:%d] failed to update collected native tokens list\n", __func__, __LINE__);
            native_tokens_free(collected_native_tokens);
            get_output_response_free(input_res);
            return -1;
          }

          // add unspent output into unspent outputs list
          if (utxo_outputs_add(unspent_outputs, OUTPUT_ALIAS, output_alias) != 0) {
            printf("[%s:%d] can not add unspent output to unspent outputs list\n", __func__, __LINE__);
            native_tokens_free(collected_native_tokens);
            get_output_response_free(input_res);
            return -1;
          }

          // add unspent output into a transaction essence
          if (tx_essence_add_input(essence, 0, input_res->u.data->meta.tx_id, input_res->u.data->meta.output_index) !=
              0) {
            printf("[%s:%d] can not add unspent output to transaction essence\n", __func__, __LINE__);
            native_tokens_free(collected_native_tokens);
            get_output_response_free(input_res);
            return -1;
          }

          break;
        }
        case OUTPUT_FOUNDRY: {
          output_foundry_t* output_foundry = input_res->u.data->output->output;

          // update collected amount
          collected_amount += output_foundry->amount;

          // update collected native tokens
          if (update_collected_native_tokens(output_foundry->native_tokens, &collected_native_tokens) != 0) {
            printf("[%s:%d] failed to update collected native tokens list\n", __func__, __LINE__);
            native_tokens_free(collected_native_tokens);
            get_output_response_free(input_res);
            return -1;
          }

          // add unspent output into unspent outputs list
          if (utxo_outputs_add(unspent_outputs, OUTPUT_FOUNDRY, output_foundry) != 0) {
            printf("[%s:%d] can not add unspent output to unspent outputs list\n", __func__, __LINE__);
            native_tokens_free(collected_native_tokens);
            get_output_response_free(input_res);
            return -1;
          }

          // add unspent output into a transaction essence
          if (tx_essence_add_input(essence, 0, input_res->u.data->meta.tx_id, input_res->u.data->meta.output_index) !=
              0) {
            printf("[%s:%d] can not add unspent output to transaction essence\n", __func__, __LINE__);
            native_tokens_free(collected_native_tokens);
            get_output_response_free(input_res);
            return -1;
          }

          break;
        }
        case OUTPUT_NFT: {
          output_nft_t* output_nft = input_res->u.data->output->output;

          // update collected amount
          collected_amount += output_nft->amount;

          // update collected native tokens
          if (update_collected_native_tokens(output_nft->native_tokens, &collected_native_tokens) != 0) {
            printf("[%s:%d] failed to update collected native tokens list\n", __func__, __LINE__);
            native_tokens_free(collected_native_tokens);
            get_output_response_free(input_res);
            return -1;
          }

          // add unspent output into unspent outputs list
          if (utxo_outputs_add(unspent_outputs, OUTPUT_NFT, output_nft) != 0) {
            printf("[%s:%d] can not add unspent output to unspent outputs list\n", __func__, __LINE__);
            native_tokens_free(collected_native_tokens);
            get_output_response_free(input_res);
            return -1;
          }

          // add unspent output into a transaction essence
          if (tx_essence_add_input(essence, 0, input_res->u.data->meta.tx_id, input_res->u.data->meta.output_index) !=
              0) {
            printf("[%s:%d] can not add unspent output to transaction essence\n", __func__, __LINE__);
            native_tokens_free(collected_native_tokens);
            get_output_response_free(input_res);
            return -1;
          }

          break;
        }
        case OUTPUT_SINGLE_OUTPUT:
        case OUTPUT_DUST_ALLOWANCE:
        case OUTPUT_TREASURY:
        default:
          printf("[%s:%d] unsupported output type\n", __func__, __LINE__);
          break;
      }

      get_output_response_free(input_res);
    }
  }

  uint64_t send_amount = 0;
  native_tokens_list_t* send_native_tokens = native_tokens_new();

  utxo_outputs_list_t* output_elm;
  LL_FOREACH(outputs, output_elm) {
    switch (output_elm->output->output_type) {
      case OUTPUT_BASIC: {
        output_basic_t* output_basic = output_elm->output->output;

        // update send amount
        send_amount += output_basic->amount;

        // update send native tokens
        if (update_collected_native_tokens(output_basic->native_tokens, &send_native_tokens) != 0) {
          printf("[%s:%d] failed to update send native tokens list\n", __func__, __LINE__);
          native_tokens_free(collected_native_tokens);
          native_tokens_free(send_native_tokens);
          return -1;
        }

        break;
      }
      case OUTPUT_ALIAS: {
        output_alias_t* output_alias = output_elm->output->output;

        // update send amount
        send_amount += output_alias->amount;

        // update send native tokens
        if (update_collected_native_tokens(output_alias->native_tokens, &send_native_tokens) != 0) {
          printf("[%s:%d] failed to update send native tokens list\n", __func__, __LINE__);
          native_tokens_free(collected_native_tokens);
          native_tokens_free(send_native_tokens);
          return -1;
        }

        break;
      }
      case OUTPUT_FOUNDRY: {
        output_foundry_t* output_foundry = output_elm->output->output;

        // update send amount
        send_amount += output_foundry->amount;

        // update send native tokens
        if (update_collected_native_tokens(output_foundry->native_tokens, &send_native_tokens) != 0) {
          printf("[%s:%d] failed to update send native tokens list\n", __func__, __LINE__);
          native_tokens_free(collected_native_tokens);
          native_tokens_free(send_native_tokens);
          return -1;
        }

        break;
      }
      case OUTPUT_NFT: {
        output_nft_t* output_nft = output_elm->output->output;

        // update send amount
        send_amount += output_nft->amount;

        // update send native tokens
        if (update_collected_native_tokens(output_nft->native_tokens, &send_native_tokens) != 0) {
          printf("[%s:%d] failed to update send native tokens list\n", __func__, __LINE__);
          native_tokens_free(collected_native_tokens);
          native_tokens_free(send_native_tokens);
          return -1;
        }

        break;
      }
      case OUTPUT_SINGLE_OUTPUT:
      case OUTPUT_DUST_ALLOWANCE:
      case OUTPUT_TREASURY:
      default:
        native_tokens_free(collected_native_tokens);
        native_tokens_free(send_native_tokens);
        return -1;
    }
  }

  uint64_t remainder_amount = 0;
  native_tokens_list_t* remainder_native_tokens = native_tokens_new();

  if (collected_amount >= send_amount) {
    // check if remainder output is needed
    if (wallet_calculate_remainder_amount(send_amount, collected_amount, send_native_tokens, collected_native_tokens,
                                          &remainder_amount, &remainder_native_tokens) != 0) {
      printf("[%s:%d] can not calculate a remainder amount\n", __func__, __LINE__);
      native_tokens_free(collected_native_tokens);
      native_tokens_free(remainder_native_tokens);
      native_tokens_free(send_native_tokens);
      return -1;
    }

    // check inputs balance (base tokens and native tokens)
    if (wallet_is_collected_balance_sufficient(w, send_amount, collected_amount, remainder_amount, send_native_tokens,
                                               collected_native_tokens, remainder_native_tokens)) {
      // amount of base tokens and native tokens is sufficient, we can exit collecting more unspent outputs
      *balance_sufficient = true;
      // create a remainder output (remainder balance is returned to the sender address) if needed
      if (remainder_amount > 0) {
        *remainder = wallet_output_basic_create(sender_addr, remainder_amount, remainder_native_tokens);
        if (!*remainder) {
          printf("[%s:%d] can not create a reminder basic output\n", __func__, __LINE__);
          native_tokens_free(collected_native_tokens);
          native_tokens_free(remainder_native_tokens);
          native_tokens_free(send_native_tokens);
          return -1;
        }

        native_tokens_free(collected_native_tokens);
        native_tokens_free(remainder_native_tokens);
        native_tokens_free(send_native_tokens);

        return 0;
      }

      native_tokens_free(collected_native_tokens);
      native_tokens_free(remainder_native_tokens);
      native_tokens_free(send_native_tokens);

      return 0;
    }
  }

  res_outputs_id_t* res_ids = get_unspent_basic_output_ids(w, sender_addr);
  if (!res_ids) {
    printf("[%s:%d] failed to get unspent basic output IDs\n", __func__, __LINE__);
    return -1;
  }

  int ret = 0;

  // fetch output data from output IDs
  for (size_t i = 0; i < res_outputs_output_id_count(res_ids); i++) {
    res_output_t* output_res = get_output_response_new();
    if (!output_res) {
      printf("[%s:%d] failed to create output response object\n", __func__, __LINE__);
      ret = -1;
      goto end;
    }

    if (get_output(&w->endpoint, res_outputs_output_id(res_ids, i), output_res) != 0) {
      printf("[%s:%d] failed to get output from a node\n", __func__, __LINE__);
      get_output_response_free(output_res);
      ret = -1;
      goto end;
    }

    if (output_res->is_error) {
      printf("[%s:%d] %s\n", __func__, __LINE__, output_res->u.error->msg);
      get_output_response_free(output_res);
      ret = -1;
      goto end;
    }

    // check if unspent output is already consumed
    utxo_inputs_list_t* input_elm;
    if (inputs) {
      LL_FOREACH(inputs, input_elm) {
        if (memcpy(output_res->u.data->meta.tx_id, input_elm->input->tx_id, IOTA_TRANSACTION_ID_BYTES) == 0 &&
            output_res->u.data->meta.output_index == input_elm->input->output_index) {
          continue;
        }
      }
    }

    if (output_res->u.data->output->output_type == OUTPUT_BASIC) {
      output_basic_t* output_basic = output_res->u.data->output->output;

      // check if input has any useful amount of base token or native tokens
      if (!is_unspent_basic_output_useful(w, output_basic, send_amount, collected_amount, remainder_amount,
                                          send_native_tokens, collected_native_tokens, remainder_native_tokens)) {
        get_output_response_free(output_res);
        continue;
      }

      // add input into inputs list
      if ((ret = utxo_outputs_add(unspent_outputs, OUTPUT_BASIC, output_basic)) != 0) {
        printf("[%s:%d] can not add input to inputs list\n", __func__, __LINE__);
        get_output_response_free(output_res);
        goto end;
      }

      // add input into a transaction essence
      if ((ret = tx_essence_add_input(essence, 0, output_res->u.data->meta.tx_id,
                                      output_res->u.data->meta.output_index) != 0)) {
        printf("[%s:%d] can not add input to transaction essence\n", __func__, __LINE__);
        get_output_response_free(output_res);
        goto end;
      }

      // update collected amount
      collected_amount += output_basic->amount;

      // update collected native tokens
      native_tokens_list_t* elm;
      LL_FOREACH(output_basic->native_tokens, elm) {
        native_token_t* token = native_tokens_find_by_id(collected_native_tokens, elm->token->token_id);
        if (token) {
          if (uint256_add(&token->amount, &token->amount, &elm->token->amount) != true) {
            printf("[%s:%d] can not add amount of two native tokens\n", __func__, __LINE__);
            get_output_response_free(output_res);
            ret = -1;
            goto end;
          }
        } else {
          if ((ret = native_tokens_add(&collected_native_tokens, elm->token->token_id, &elm->token->amount)) != 0) {
            printf("[%s:%d] can not add native token to a list\n", __func__, __LINE__);
            get_output_response_free(output_res);
            goto end;
          }
        }
      }

      // check if remainder output is needed
      remainder_amount = 0;
      native_tokens_free(remainder_native_tokens);
      remainder_native_tokens = NULL;
      if (wallet_calculate_remainder_amount(send_amount, collected_amount, send_native_tokens, collected_native_tokens,
                                            &remainder_amount, &remainder_native_tokens) != 0) {
        printf("[%s:%d] can not calculate a remainder amount\n", __func__, __LINE__);
        get_output_response_free(output_res);
        ret = -1;
        goto end;
      }

      // check inputs balance (base tokens and native tokens)
      if (wallet_is_collected_balance_sufficient(w, send_amount, collected_amount, remainder_amount, send_native_tokens,
                                                 collected_native_tokens, remainder_native_tokens)) {
        // amount of base tokens and native tokens is sufficient, we can exit collecting more inputs
        get_output_response_free(output_res);
        break;
      }
    }

    get_output_response_free(output_res);
  }

  // check inputs balance (base tokens and native tokens) again because there could be no more available inputs but
  // balance of base tokens and native tokens could still be too little
  if (wallet_is_collected_balance_sufficient(w, send_amount, collected_amount, remainder_amount, send_native_tokens,
                                             collected_native_tokens, remainder_native_tokens)) {
    *balance_sufficient = true;
    // create a remainder output (remainder balance is returned to the sender address) if needed
    if (remainder_amount > 0) {
      *remainder = wallet_output_basic_create(sender_addr, remainder_amount, remainder_native_tokens);
      if (!*remainder) {
        printf("[%s:%d] can not create a reminder basic output\n", __func__, __LINE__);
        ret = -1;
        goto end;
      }
    }
  }

end:
  // clean up memory
  native_tokens_free(collected_native_tokens);
  native_tokens_free(remainder_native_tokens);
  native_tokens_free(send_native_tokens);
  res_outputs_free(res_ids);
  if (ret != 0) {
    utxo_outputs_free(*unspent_outputs);
  }

  return ret;
}

int wallet_send(iota_wallet_t* w, address_t* sender_addr, ed25519_keypair_t* sender_keypair, utxo_inputs_list_t* inputs,
                utxo_outputs_list_t* outputs, native_tokens_list_t* minted_tokens, byte_t payload_id[],
                res_send_block_t* blk_res) {
  if (w == NULL || sender_addr == NULL || sender_keypair == NULL || outputs == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // create a tx
  transaction_payload_t* tx = tx_payload_new(w->network_id);
  if (!tx) {
    printf("[%s:%d] create tx payload failed\n", __func__, __LINE__);
    return -1;
  }

  // add outputs to tx essence
  utxo_outputs_list_t* elm;
  LL_FOREACH(outputs, elm) {
    if (tx_essence_add_output(tx->essence, elm->output->output_type, elm->output->output) != 0) {
      printf("[%s:%d] can not add output to transaction essence\n", __func__, __LINE__);
      tx_payload_free(tx);
      return -1;
    }
  }

  // get unspent outputs from a sender address
  utxo_outputs_list_t* unspent_outputs = NULL;
  output_basic_t* remainder = NULL;
  bool balance_sufficient = false;
  if (wallet_get_unspent_outputs_and_create_remainder(w, tx->essence, sender_addr, inputs, outputs, minted_tokens,
                                                      &balance_sufficient, &unspent_outputs, &remainder) != 0) {
    printf("[%s:%d] can not collect unspent outputs or create a reminder output\n", __func__, __LINE__);
    tx_payload_free(tx);
    return -1;
  }

  // check if balance has enough amount of tokens
  if (!balance_sufficient) {
    printf("[%s:%d] insufficient address balance\n", __func__, __LINE__);
    utxo_outputs_free(unspent_outputs);
    output_basic_free(remainder);
    tx_payload_free(tx);
    return -1;
  }

  // if remainder is needed, create a remainder output
  if (remainder) {
    if (tx_essence_add_output(tx->essence, OUTPUT_BASIC, remainder) != 0) {
      printf("[%s:%d] can not add remainder output to transaction essence\n", __func__, __LINE__);
      utxo_outputs_free(unspent_outputs);
      output_basic_free(remainder);
      tx_payload_free(tx);
      return -1;
    }
  }

  // create signature for all collected inputs
  signing_data_list_t* sign_data = signing_new();
  if (create_signatures_for_inputs(unspent_outputs, sender_keypair, &sign_data) != 0) {
    printf("[%s:%d] can not create signatures for inputs\n", __func__, __LINE__);
    utxo_outputs_free(unspent_outputs);
    output_basic_free(remainder);
    tx_payload_free(tx);
    return -1;
  }

  // create a core block
  core_block_t* block = wallet_create_core_block(w, tx, unspent_outputs, sign_data);
  if (!block) {
    printf("[%s:%d] can not create a core block\n", __func__, __LINE__);
    utxo_outputs_free(unspent_outputs);
    output_basic_free(remainder);
    signing_free(sign_data);
    tx_payload_free(tx);
    return -1;
  }

  // calculate transaction payload ID
  if (tx_payload_calculate_id(tx, payload_id, CRYPTO_BLAKE2B_256_HASH_BYTES) != 0) {
    printf("[%s:%d] can not calculate transaction payload ID\n", __func__, __LINE__);
    utxo_outputs_free(unspent_outputs);
    output_basic_free(remainder);
    signing_free(sign_data);
    core_block_free(block);
    return -1;
  }

  // send a block to a network
  int result = wallet_send_block(w, block, blk_res);

  // clean memory
  utxo_outputs_free(unspent_outputs);
  output_basic_free(remainder);
  signing_free(sign_data);
  core_block_free(block);

  return result;
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
