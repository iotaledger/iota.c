// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <mcheck.h>
#include <stdio.h>

#include "core/models/outputs/output_basic.h"
#include "core/models/payloads/transaction.h"
#include "core/models/unlock_block.h"

static output_basic_t* create_output_basic() {
  // create random ED25519 address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(addr.address, ED25519_PUBKEY_BYTES);

  // create Unlock Conditions
  cond_blk_list_t* unlock_conds = cond_blk_list_new();
  unlock_cond_blk_t* unlock_addr = cond_blk_addr_new(&addr);
  cond_blk_list_add(&unlock_conds, unlock_addr);
  cond_blk_free(unlock_addr);

  // create Basic Output
  output_basic_t* output = output_basic_new(123456789, NULL, unlock_conds, NULL);

  // clean up memory
  cond_blk_list_free(unlock_conds);

  return output;
}

int main() {
  // enable memory tracing
  mtrace();

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

  // disable memory tracing
  muntrace();

  return 0;
}
