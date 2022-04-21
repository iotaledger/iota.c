// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifdef MTRACE_ENABLED
#include <mcheck.h>
#endif
#include <stdio.h>

#include "core/models/outputs/native_tokens.h"
#include "core/models/outputs/output_basic.h"
#include "core/models/payloads/transaction.h"
#include "core/models/unlock_block.h"

static output_basic_t* create_output_basic() {
  // create random ED25519 address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(addr.address, ED25519_PUBKEY_BYTES);

  // create unlock conditions
  unlock_cond_blk_t* unlock_addr = cond_blk_addr_new(&addr);
  unlock_cond_blk_t* unlock_storage = cond_blk_storage_new(&addr, 357500);
  unlock_cond_blk_t* unlock_timelock = cond_blk_timelock_new(1200, 164330008);
  unlock_cond_blk_t* unlock_expir = cond_blk_expir_new(&addr, 1200, 164330008);
  cond_blk_list_t* unlock_conds = cond_blk_list_new();
  cond_blk_list_add(&unlock_conds, unlock_storage);
  cond_blk_list_add(&unlock_conds, unlock_addr);
  cond_blk_list_add(&unlock_conds, unlock_expir);
  cond_blk_list_add(&unlock_conds, unlock_timelock);
  cond_blk_free(unlock_addr);
  cond_blk_free(unlock_storage);
  cond_blk_free(unlock_timelock);
  cond_blk_free(unlock_expir);

  // create feature blocks
  byte_t test_meta[] = "Test tagged data from a benchmark application";
  byte_t test_tag[] = "Test tag from a benchmark application.";
  feat_blk_list_t* feat_blocks = feat_blk_list_new();
  feat_blk_list_add_tag(&feat_blocks, test_tag, sizeof(test_tag));
  feat_blk_list_add_sender(&feat_blocks, &addr);
  feat_blk_list_add_metadata(&feat_blocks, test_meta, sizeof(test_meta));

  // create native tokens
  uint256_t* amount = uint256_from_str("123456789987654321123456789987654321");
  byte_t token_id1[NATIVE_TOKEN_ID_BYTES] = {
      0xDD, 0xA7, 0xC5, 0x79, 0x47, 0x9E, 0xC, 0x93, 0xCE, 0xA7, 0x93, 0x95, 0x41, 0xF8, 0x93, 0x4D, 0xF,  0x7E, 0x3A,
      0x4,  0xCA, 0x52, 0xF8, 0x8B, 0x9B, 0x0, 0x25, 0xC0, 0xBE, 0x4A, 0xF6, 0x23, 0x59, 0x98, 0x6F, 0x64, 0xEF, 0x14};
  native_tokens_list_t* native_tokens = native_tokens_new();
  native_tokens_add(&native_tokens, token_id1, amount);
  uint256_free(amount);

  // create Basic Output
  output_basic_t* output = output_basic_new(357800, native_tokens, unlock_conds, feat_blocks);

  // clean up memory
  cond_blk_list_free(unlock_conds);
  feat_blk_list_free(feat_blocks);
  native_tokens_free(native_tokens);

  return output;
}

int main() {
#ifdef MTRACE_ENABLED
  // enable memory tracing
  mtrace();
#endif

  uint16_t network_id = 2;
  transaction_essence_t* es = tx_essence_new(network_id);
  if (!es) {
    printf("[%s:%d]: Can not create transaction essence object!\n", __func__, __LINE__);
    return -1;
  }

  // add input
  byte_t tx_id0[IOTA_TRANSACTION_ID_BYTES] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  if (tx_essence_add_input(es, 0, tx_id0, 1) != 0) {
    printf("[%s:%d]: Can not add input to a transaction!\n", __func__, __LINE__);
    tx_essence_free(es);
    return -1;
  }

  // add basic output to the outputs list
  output_basic_t* basic_output = create_output_basic();
  if (!basic_output) {
    printf("[%s:%d]: Can not create Basic output object!\n", __func__, __LINE__);
    tx_essence_free(es);
    return -1;
  }
  if (tx_essence_add_output(es, OUTPUT_BASIC, basic_output) != 0) {
    printf("[%s:%d]: Can not add output to a transaction!\n", __func__, __LINE__);
    output_basic_free(basic_output);
    tx_essence_free(es);
    return -1;
  }

  // add the output in unspent outputs list to be able to calculate inputs commitment hash
  utxo_outputs_list_t* unspent_outputs = utxo_outputs_new();
  if (utxo_outputs_add(&unspent_outputs, OUTPUT_BASIC, basic_output) != 0) {
    printf("[%s:%d]: Can not add unspent output to the list!\n", __func__, __LINE__);
    output_basic_free(basic_output);
    utxo_outputs_free(unspent_outputs);
    tx_essence_free(es);
  }
  output_basic_free(basic_output);

  // calculate inputs commitment
  if (tx_essence_inputs_commitment_calculate(es, unspent_outputs) != 0) {
    printf("[%s:%d]: Can not calculate inputs commitment!\n", __func__, __LINE__);
    utxo_outputs_free(unspent_outputs);
    tx_essence_free(es);
  }
  utxo_outputs_free(unspent_outputs);

  // syntactic validation
  byte_cost_config_t* cost = byte_cost_config_default_new();
  if (!cost) {
    printf("[%s:%d]: Can not create byte cost configuration object!\n", __func__, __LINE__);
    tx_essence_free(es);
    return -1;
  }

  if (tx_essence_syntactic(es, cost) != true) {
    printf("[%s:%d]: Transaction syntactic validation failed!\n", __func__, __LINE__);
    byte_cost_config_free(cost);
    tx_essence_free(es);
    return -1;
  }
  byte_cost_config_free(cost);

  // print transaction
  tx_essence_print(es, 0);

  // clean up
  tx_essence_free(es);

  return 0;
}
