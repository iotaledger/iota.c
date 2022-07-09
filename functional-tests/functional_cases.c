// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>  // for Linux sleep()

#include "client/api/restful/faucet_enqueue.h"
#include "client/api/restful/get_block.h"
#include "client/api/restful/get_block_metadata.h"
#include "client/api/restful/get_milestone.h"
#include "client/api/restful/get_node_info.h"
#include "client/api/restful/get_output.h"
#include "client/api/restful/get_outputs_id.h"
#include "client/api/restful/get_tips.h"
#include "client/api/restful/get_transaction_included_block.h"
#include "client/api/restful/send_tagged_data.h"
#include "core/utils/bech32.h"
#include "functional_cases.h"
#include "wallet/output_basic.h"

static int get_info(test_config_t* conf, test_data_t* params, test_item_t* items) {
  if (!conf || !params || !items) {
    printf("[%s:%d] invalid params\n", __func__, __LINE__);
    return -1;
  }

  res_node_info_t* info = res_node_info_new();
  if (info) {
    int ret = get_node_info(&conf->node_config, info);
    if (ret == 0) {
      if (info->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, info->u.error->msg);
      } else {
        if (conf->show_payload) {
          node_info_print(info, 0);
        }
        printf("[%s:%d] GET /info: PASS\n", __func__, __LINE__);
        items[CORE_GET_NODE_INFO].st = STATE_PASS;
      }
    } else {
      printf("[%s:%d] performed get_node_info failed\n", __func__, __LINE__);
      res_node_info_free(info);
      return ret;
    }
    res_node_info_free(info);
  } else {
    printf("[%s:%d] allocate the node info response failed\n", __func__, __LINE__);
  }
  return 0;
}

static int restful_get_tips(test_config_t* conf, test_data_t* params, test_item_t* items) {
  if (!conf || !params || !items) {
    printf("[%s:%d] invalid params\n", __func__, __LINE__);
    return -1;
  }

  res_tips_t* tips = res_tips_new();
  if (tips) {
    int ret = get_tips(&conf->node_config, tips);
    if (ret == 0) {
      if (tips->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, tips->u.error->msg);
      } else {
        if (get_tips_id_count(tips) > 0) {
          printf("[%s:%d] GET /tips: PASS\n", __func__, __LINE__);
          items[CORE_GET_TIPS].st = STATE_PASS;
        } else {
          printf("[%s:%d] empty tips\n", __func__, __LINE__);
          items[CORE_GET_TIPS].st = STATE_NG;
        }
      }
    } else {
      printf("[%s:%d] performed get_tips failed\n", __func__, __LINE__);
      res_tips_free(tips);
      items[CORE_GET_TIPS].st = STATE_NG;
      return ret;
    }
    res_tips_free(tips);
  } else {
    printf("[%s:%d] allocate the tips response failed\n", __func__, __LINE__);
  }
  return 0;
}

static int init_wallet(test_config_t* conf, test_data_t* params, test_item_t* items) {
  if (!conf || !params || !items) {
    printf("[%s:%d] invalid params\n", __func__, __LINE__);
    return -1;
  }

  int ret = 0;
  params->w = wallet_create(conf->mnemonic, "", conf->coin_type, 0);
  if (!params->w) {
    printf("[%s:%d] wallet create failed\n", __func__, __LINE__);
    return -1;
  }

  ret = wallet_set_endpoint(params->w, conf->node_config.host, conf->node_config.port, conf->node_config.use_tls);
  if (ret != 0) {
    printf("[%s:%d] wallet set endpoint failed\n", __func__, __LINE__);
    wallet_destroy(params->w);
    return -1;
  }

  // validating /info
  ret = wallet_update_node_config(params->w);
  if (ret != 0) {
    printf("[%s:%d] wallet get node info failed\n", __func__, __LINE__);
    wallet_destroy(params->w);
    return -1;
  }
  items[CORE_GET_NODE_INFO].st = STATE_PASS;
  return 0;
}

static int request_token(test_config_t* conf, test_data_t* params, test_item_t* items) {
  if (!conf || !params || !items) {
    printf("[%s:%d] invalid params\n", __func__, __LINE__);
    return -1;
  }

  int ret = 0;
  res_faucet_enqueue_t res = {};
  char sender_bech32[BECH32_MAX_STRING_LEN + 1] = {};

  ret = wallet_ed25519_address_from_index(params->w, false, conf->sender_index, &params->sender);
  if (ret != 0) {
    printf("[%s:%d] derive sender address failed\n", __func__, __LINE__);
    return -1;
  }

  ret = address_to_bech32(&params->sender, params->w->bech32HRP, sender_bech32, sizeof(sender_bech32));
  if (ret != 0) {
    printf("[%s:%d] get bech32 address failed\n", __func__, __LINE__);
    return -1;
  }

  // Test bech32 address with invalid len
  ret = req_tokens_to_addr_from_faucet(&conf->faucet_config, sender_bech32, &res);
  if (ret == 0) {
    if (res.is_error == true) {
      if (strstr(res.u.error->msg, "have enough funds")) {
        printf("[%s:%d] POST faucet enqueue: PASS - have enough funds\n", __func__, __LINE__);
        items[FAUCET_GET_ENQUEUE].st = STATE_PASS;
        res_err_free(res.u.error);
      } else {
        printf("[%s:%d] request token err: %s\n", __func__, __LINE__, res.u.error->msg);
        items[FAUCET_GET_ENQUEUE].st = STATE_NG;
        res_err_free(res.u.error);
        return -1;
      }
    } else {
      printf("request token: %s\n", sender_bech32);
      printf("[%s:%d] POST faucet enqueue: PASS\n", __func__, __LINE__);
      items[FAUCET_GET_ENQUEUE].st = STATE_PASS;
    }
  }
  return ret;
}

static int send_basic_tx(test_config_t* conf, test_data_t* params, test_item_t* items) {
  if (!conf || !params || !items) {
    printf("[%s:%d] invalid params\n", __func__, __LINE__);
    return -1;
  }

  int ret = 0;
  res_send_block_t block_res = {};

  ret = wallet_ed25519_address_from_index(params->w, false, conf->receiver_index, &params->recv);
  if (ret != 0) {
    printf("[%s:%d] derive receiver address failed\n", __func__, __LINE__);
    return -1;
  }

  ret = wallet_ed25519_address_from_index(params->w, false, conf->sender_index, &params->sender);
  if (ret != 0) {
    printf("[%s:%d] get sender address failed\n", __func__, __LINE__);
    return -1;
  }

  // validating /tips and /block with basic outputs
  // send 1Mi to receiver
  printf("Basic sender: ");
  address_print(&params->sender);
  printf("Basic receiver: ");
  address_print(&params->recv);
  ret = wallet_basic_output_send(params->w, false, conf->sender_index, 1000000, NULL, &params->recv, &block_res);
  if (ret == 0) {
    if (block_res.is_error) {
      printf("[%s:%d] Error: %s\n", __func__, __LINE__, block_res.u.error->msg);
      res_err_free(block_res.u.error);
      items[CORE_POST_BASIC_MSG].st = STATE_NG;
      return -1;
    } else {
      strncpy(params->basic_blk_id, block_res.u.blk_id, BIN_TO_HEX_STR_BYTES(IOTA_BLOCK_ID_BYTES));
      printf("[%s:%d] Basic Block ID: %s\n", __func__, __LINE__, block_res.u.blk_id);
      printf("[%s:%d] GET /tips: PASS\n", __func__, __LINE__);
      printf("[%s:%d] POST /block: PASS\n", __func__, __LINE__);
      items[CORE_GET_TIPS].st = STATE_PASS;
      items[CORE_POST_BASIC_MSG].st = STATE_PASS;
    }
  } else {
    printf("[%s:%d] send block failed\n", __func__, __LINE__);
    items[CORE_POST_BASIC_MSG].st = STATE_NG;
    return -1;
  }
  return 0;
}

static int send_tagged_payload(test_config_t* conf, test_data_t* params, test_item_t* items) {
  if (!conf || !params || !items) {
    printf("[%s:%d] invalid params\n", __func__, __LINE__);
    return -1;
  }

  int ret = 0;
  res_send_block_t res = {};
  byte_t tag[8];
  iota_crypto_randombytes(tag, 8);
  byte_t tag_data[64];
  iota_crypto_randombytes(tag_data, 64);

  ret = send_tagged_data_block(&params->w->endpoint, params->w->protocol_version, tag, sizeof(tag), tag_data,
                               sizeof(tag_data), &res);
  if (ret == 0) {
    if (res.is_error) {
      printf("[%s:%d]Err: %s\n", __func__, __LINE__, res.u.error->msg);
      res_err_free(res.u.error);
      items[CORE_POST_TAGGED_MSG].st = STATE_NG;
      return -1;
    } else {
      strncpy(params->tagged_blk_id, res.u.blk_id, BIN_TO_HEX_STR_BYTES(IOTA_BLOCK_ID_BYTES));
      printf("[%s:%d] Tagged Data Block ID: %s\n", __func__, __LINE__, res.u.blk_id);
      items[CORE_POST_TAGGED_MSG].st = STATE_PASS;
    }
  } else {
    printf("[%s:%d] performed send_tagged_data_block failed\n", __func__, __LINE__);
    items[CORE_POST_TAGGED_MSG].st = STATE_NG;
  }
  return ret;
}

static int fetch_milestone(test_config_t* conf, test_data_t* params, test_item_t* items) {
  if (!conf || !params || !items) {
    printf("[%s:%d] invalid params\n", __func__, __LINE__);
    return -1;
  }

  int ret = 0;

  // validatin /milestones/by-index/{index}
  res_milestone_t* res_ml = res_milestone_new();
  if (res_ml) {
    // get milestone of index 2
    ret = get_milestone_by_index(&params->w->endpoint, 2, res_ml);
    if (ret == 0) {
      if (res_ml->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, res_ml->u.error->msg);
        items[CORE_GET_MILESTONES_INDEX].st = STATE_NG;
        res_milestone_free(res_ml);
        return -1;
      } else {
        if (conf->show_payload) {
          milestone_payload_print(res_ml->u.ms, 0);
        }
        bin_2_hex(res_ml->u.ms->previous_milestone_id, sizeof(res_ml->u.ms->previous_milestone_id), NULL,
                  params->milestone_blk_id, sizeof(params->milestone_blk_id));
        printf("[%s:%d] Milestone ID: %s\n", __func__, __LINE__, params->milestone_blk_id);
        printf("[%s:%d] GET /milestones/by-index/{index}: PASS\n", __func__, __LINE__);
        items[CORE_GET_MILESTONES_INDEX].st = STATE_PASS;
      }
    } else {
      printf("[%s:%d] performed get_milestone_by_index failed\n", __func__, __LINE__);
      items[CORE_GET_MILESTONES_INDEX].st = STATE_NG;
      res_milestone_free(res_ml);
      return -1;
    }
  } else {
    printf("[%s:%d] allocate milestone response failed\n", __func__, __LINE__);
    return -1;
  }
  res_milestone_free(res_ml);
  res_ml = NULL;

  // validatin /milestones/{milestoneId}
  byte_t empty_milstone_id[IOTA_BLOCK_ID_BYTES] = {};
  res_ml = res_milestone_new();
  if (res_ml) {
    // get milestone by ID
    ret = get_milestone_by_id(&params->w->endpoint, params->milestone_blk_id, res_ml);
    if (ret == 0) {
      if (res_ml->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, res_ml->u.error->msg);
        items[CORE_GET_MILESTONES].st = STATE_NG;
        res_milestone_free(res_ml);
        return -1;
      } else {
        if (conf->show_payload) {
          milestone_payload_print(res_ml->u.ms, 0);
        }
        // the previous_milestone_id should be empty since we are query milestone index 1
        if (memcmp(empty_milstone_id, res_ml->u.ms->previous_milestone_id, sizeof(empty_milstone_id)) == 0) {
          printf("[%s:%d] GET /milestones/{milestoneId}: PASS\n", __func__, __LINE__);
          items[CORE_GET_MILESTONES].st = STATE_PASS;
        } else {
          printf("[%s:%d] previous_milestone_id is not expected\n", __func__, __LINE__);
          items[CORE_GET_MILESTONES].st = STATE_NG;
          res_milestone_free(res_ml);
          return -1;
        }
      }
    } else {
      printf("[%s:%d] performed get_milestone_by_id failed\n", __func__, __LINE__);
      items[CORE_GET_MILESTONES].st = STATE_NG;
      res_milestone_free(res_ml);
      return -1;
    }
  } else {
    printf("[%s:%d] allocate milestone response failed\n", __func__, __LINE__);
    return -1;
  }
  res_milestone_free(res_ml);

  // validatin /milestones/by-index/{index}/utxo_changes
  res_utxo_changes_t* res_ml_utxo = res_utxo_changes_new();
  if (res_ml_utxo) {
    ret = get_utxo_changes_by_ms_index(&params->w->endpoint, 2, res_ml_utxo);
    if (ret == 0) {
      if (res_ml_utxo->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, res_ml_utxo->u.error->msg);
        items[CORE_GET_MILESTONES_INDEX_UTXO].st = STATE_NG;
        res_utxo_changes_free(res_ml_utxo);
        return -1;
      } else {
        if (conf->show_payload) {
          print_utxo_changes(res_ml_utxo, 0);
        }
        printf("[%s:%d] GET /milestones/by-index/{index}/utxo_changes: PASS\n", __func__, __LINE__);
        items[CORE_GET_MILESTONES_INDEX_UTXO].st = STATE_PASS;
      }
    } else {
      printf("[%s:%d] performed get_utxo_changes_by_ms_index failed\n", __func__, __LINE__);
      items[CORE_GET_MILESTONES_INDEX_UTXO].st = STATE_NG;
      res_milestone_free(res_ml);
      return -1;
    }
  } else {
    printf("[%s:%d] allocate milestone UTXO response failed\n", __func__, __LINE__);
    return -1;
  }
  res_utxo_changes_free(res_ml_utxo);
  res_ml_utxo = NULL;

  // validatin /milestones/{milestoneId}/utxo_changes
  res_ml_utxo = res_utxo_changes_new();
  if (res_ml_utxo) {
    ret = get_utxo_changes_by_ms_id(&params->w->endpoint, params->milestone_blk_id, res_ml_utxo);
    if (ret == 0) {
      if (res_ml_utxo->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, res_ml_utxo->u.error->msg);
        items[CORE_GET_MILESTONES_UTXO].st = STATE_NG;
        res_utxo_changes_free(res_ml_utxo);
        return -1;
      } else {
        if (conf->show_payload) {
          print_utxo_changes(res_ml_utxo, 0);
        }
        printf("[%s:%d] GET /milestones/{milestoneId}/utxo_changes: PASS\n", __func__, __LINE__);
        items[CORE_GET_MILESTONES_UTXO].st = STATE_PASS;
      }
    } else {
      printf("[%s:%d] performed get_utxo_changes_by_ms_id failed\n", __func__, __LINE__);
      items[CORE_GET_MILESTONES_UTXO].st = STATE_NG;
      res_milestone_free(res_ml);
      return -1;
    }
  } else {
    printf("[%s:%d] allocate milestone utxo response failed\n", __func__, __LINE__);
    return -1;
  }
  res_utxo_changes_free(res_ml_utxo);
  return 0;
}

static int validating_blocks(test_config_t* conf, test_data_t* params, test_item_t* items) {
  if (!conf || !params || !items) {
    printf("[%s:%d] invalid params\n", __func__, __LINE__);
    return -1;
  }

  int ret = 0;
  printf("Tested Block IDs:\n");
  printf("Basic: 0x%s\n", params->basic_blk_id);
  printf("Milestone: 0x%s\n", params->milestone_blk_id);
  printf("Tagged Data: 0x%s\n", params->tagged_blk_id);

  // validating /blocks/{blockId}
  // Basic outputs
  res_block_t* block_from_id = res_block_new();
  if (block_from_id) {
    ret = get_block_by_id(&params->w->endpoint, params->basic_blk_id, block_from_id);
    if (ret == 0) {
      if (block_from_id->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, block_from_id->u.error->msg);
        res_block_free(block_from_id);
        items[CORE_GET_MSG_BASIC].st = STATE_NG;
        return -1;
      } else {
        if (conf->show_payload) {
          core_block_print(block_from_id->u.blk, 0);
        }
        items[CORE_GET_MSG_BASIC].st = STATE_PASS;
        printf("[%s:%d] GET /blocks/{blockId}: Basic Outputs PASS\n", __func__, __LINE__);
      }
    } else {
      printf("[%s:%d] performed get_block_by_id failed\n", __func__, __LINE__);
      items[CORE_GET_MSG_BASIC].st = STATE_NG;
      res_block_free(block_from_id);
      return ret;
    }
  } else {
    printf("[%s:%d] allocate block response failed\n", __func__, __LINE__);
    return -1;
  }
  res_block_free(block_from_id);
  block_from_id = NULL;

  // Milestone
  block_from_id = res_block_new();
  if (block_from_id) {
    ret = get_block_by_id(&params->w->endpoint, params->milestone_blk_id, block_from_id);
    if (ret == 0) {
      // milestone ID is not a block
      if (block_from_id->is_error) {
        printf("[%s:%d] GET /blocks/{blockId}: Milestone PASS\n", __func__, __LINE__);
        items[CORE_GET_MSG_MILESTONE].st = STATE_PASS;
      } else {
        printf("[%s:%d] GET /blocks/{blockId}: Milestone NG\n", __func__, __LINE__);
        res_block_free(block_from_id);
        items[CORE_GET_MSG_MILESTONE].st = STATE_NG;
        return -1;
      }
    } else {
      printf("[%s:%d] performed get_block_by_id failed\n", __func__, __LINE__);
      items[CORE_GET_MSG_MILESTONE].st = STATE_NG;
      res_block_free(block_from_id);
      return ret;
    }
  } else {
    printf("[%s:%d] allocate block response failed\n", __func__, __LINE__);
    return -1;
  }
  res_block_free(block_from_id);
  block_from_id = NULL;

  // Tagged block
  block_from_id = res_block_new();
  if (block_from_id) {
    ret = get_block_by_id(&params->w->endpoint, params->tagged_blk_id, block_from_id);
    if (ret == 0) {
      if (block_from_id->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, block_from_id->u.error->msg);
        res_block_free(block_from_id);
        items[CORE_GET_MSG_TAGGED].st = STATE_NG;
        return -1;
      } else {
        if (conf->show_payload) {
          core_block_print(block_from_id->u.blk, 0);
        }
        printf("[%s:%d] GET /blocks/{blockId}: Tagged Data PASS\n", __func__, __LINE__);
        items[CORE_GET_MSG_TAGGED].st = STATE_PASS;
      }
    } else {
      printf("[%s:%d] performed get_block_by_id failed\n", __func__, __LINE__);
      res_block_free(block_from_id);
      items[CORE_GET_MSG_TAGGED].st = STATE_NG;
      return ret;
    }
  } else {
    printf("[%s:%d] allocate block response failed\n", __func__, __LINE__);
    return -1;
  }
  res_block_free(block_from_id);

  // validating /blocks/{blockId}/metadata
  res_block_meta_t* meta = block_meta_new();
  if (meta) {
    ret = get_block_metadata(&params->w->endpoint, params->basic_blk_id, meta);
    if (ret == 0) {
      if (meta->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, meta->u.error->msg);
        items[CORE_GET_MSG_META_BASIC].st = STATE_NG;
        block_meta_free(meta);
        return -1;
      } else {
        if (conf->show_payload) {
          print_block_metadata(meta, 0);
        }
        printf("[%s:%d] GET /blocks/{blockId}/metadata: Basic Outputs PASS\n", __func__, __LINE__);
        items[CORE_GET_MSG_META_BASIC].st = STATE_PASS;
      }
    } else {
      printf("[%s:%d] performed get_block_metadata failed\n", __func__, __LINE__);
      items[CORE_GET_MSG_META_BASIC].st = STATE_NG;
      block_meta_free(meta);
      return ret;
    }
  } else {
    printf("[%s:%d] allocate block metadata response failed\n", __func__, __LINE__);
    return -1;
  }
  block_meta_free(meta);
  meta = NULL;
  // Milestone
  meta = block_meta_new();
  if (meta) {
    ret = get_block_metadata(&params->w->endpoint, params->milestone_blk_id, meta);
    if (ret == 0) {
      // milestone ID is not a block
      if (meta->is_error) {
        printf("[%s:%d] GET /blocks/{blockId}/metadata: Milestone PASS\n", __func__, __LINE__);
        items[CORE_GET_MSG_META_MILESTONE].st = STATE_PASS;
      } else {
        printf("[%s:%d] GET /blocks/{blockId}/metadata: Milestone NG\n", __func__, __LINE__);
        items[CORE_GET_MSG_META_MILESTONE].st = STATE_NG;
        block_meta_free(meta);
        return -1;
      }
    } else {
      printf("[%s:%d] performed get_block_metadata failed\n", __func__, __LINE__);
      items[CORE_GET_MSG_META_MILESTONE].st = STATE_NG;
      block_meta_free(meta);
      return ret;
    }
  } else {
    printf("[%s:%d] allocate block metadata response failed\n", __func__, __LINE__);
    return -1;
  }
  block_meta_free(meta);
  meta = NULL;
  // Tagged data
  meta = block_meta_new();
  if (meta) {
    ret = get_block_metadata(&params->w->endpoint, params->tagged_blk_id, meta);
    if (ret == 0) {
      if (meta->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, meta->u.error->msg);
        items[CORE_GET_MSG_META_TAGGED].st = STATE_NG;
        block_meta_free(meta);
        return -1;
      } else {
        if (conf->show_payload) {
          print_block_metadata(meta, 0);
        }
        printf("[%s:%d] GET /blocks/{blockId}/metadata: Tagged Data PASS\n", __func__, __LINE__);
        items[CORE_GET_MSG_META_TAGGED].st = STATE_PASS;
      }
    } else {
      printf("[%s:%d] performed get_block_metadata failed\n", __func__, __LINE__);
      items[CORE_GET_MSG_META_TAGGED].st = STATE_NG;
      block_meta_free(meta);
      return ret;
    }
  } else {
    printf("[%s:%d] allocate block metadata response failed\n", __func__, __LINE__);
    return -1;
  }
  block_meta_free(meta);

  return 0;
}

static int validating_indexers_basic(test_config_t* conf, test_data_t* params, test_item_t* items) {
  if (!conf || !params || !items) {
    printf("[%s:%d] invalid params\n", __func__, __LINE__);
    return -1;
  }

  int ret = 0;
  res_outputs_id_t* res_ids = NULL;

  // get bech32 address as the query paramter
  char bech32_addr[BECH32_MAX_STRING_LEN + 1] = {};
  if (address_to_bech32(&params->sender, params->w->bech32HRP, bech32_addr, sizeof(bech32_addr)) != 0) {
    printf("[%s:%d] convert sender address to bech32 address failed\n", __func__, __LINE__);
    return -1;
  }

  // prepare query filter
  outputs_query_list_t* filter = outputs_query_list_new();
  // add query paramters
  if (outputs_query_list_add(&filter, QUERY_PARAM_ADDRESS, bech32_addr) != 0) {
    printf("[%s:%d] add query parameter failed\n", __func__, __LINE__);
    outputs_query_list_free(filter);
    return -1;
  }

  // query output IDs
  res_ids = res_outputs_new();
  if (res_ids) {
    ret = get_basic_outputs(&params->w->endpoint, params->w->indexer_path, filter, res_ids);
    if (ret == 0) {
      if (res_ids->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, res_ids->u.error->msg);
        items[INDEXER_GET_BASIC].st = STATE_NG;
        outputs_query_list_free(filter);
        res_outputs_free(res_ids);
        return -1;
      } else {
        // check if there are outputs in this address
        if (res_outputs_output_id_count(res_ids) < 1) {
          printf("[%s:%d] no outputs in this address\n", __func__, __LINE__);
          outputs_query_list_free(filter);
          items[INDEXER_GET_BASIC].st = STATE_NG;
          res_outputs_free(res_ids);
          return -1;
        }
        strncpy(params->output_id, res_outputs_output_id(res_ids, 0), sizeof(params->output_id));
        printf("[%s:%d] GET /api/plugins/indexer/v1/outputs/basic: PASS\n", __func__, __LINE__);
        items[INDEXER_GET_BASIC].st = STATE_PASS;
      }
    } else {
      printf("[%s:%d] performed get_basic_outputs failed\n", __func__, __LINE__);
      items[INDEXER_GET_BASIC].st = STATE_NG;
      outputs_query_list_free(filter);
      res_outputs_free(res_ids);
      return -1;
    }

  } else {
    printf("[%s:%d] allocate the output response failed\n", __func__, __LINE__);
    outputs_query_list_free(filter);
    return -1;
  }
  outputs_query_list_free(filter);
  res_outputs_free(res_ids);

  return 0;
}

static int validating_utxo(test_config_t* conf, test_data_t* params, test_item_t* items) {
  if (!conf || !params || !items) {
    printf("[%s:%d] invalid params\n", __func__, __LINE__);
    return -1;
  }

  int ret = 0;
  printf("Testing output ID: 0x%s\n", params->basic_blk_id);

  // find an output by its ID
  res_output_t* res_output = get_output_response_new();
  if (res_output) {
    // get the output object
    if (get_output(&params->w->endpoint, params->output_id, res_output) != 0) {
      printf("[%s:%d] performed get_output failed\n", __func__, __LINE__);
      items[CORE_GET_OUTPUTS].st = STATE_NG;
      get_output_response_free(res_output);
      return -1;
    } else {
      if (res_output->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, res_output->u.error->msg);
        items[CORE_GET_OUTPUTS].st = STATE_NG;
        get_output_response_free(res_output);
        return -1;
      } else {
        if (conf->show_payload) {
          dump_get_output_response(res_output, 0);
        }
        printf("[%s:%d] GET /outputs/{outputId}: PASS\n", __func__, __LINE__);
        items[CORE_GET_OUTPUTS].st = STATE_PASS;
      }
    }
  } else {
    printf("[%s:%d] allocate output response failed\n", __func__, __LINE__);
    return -1;
  }
  get_output_response_free(res_output);
  res_output = NULL;

  // get the metadata of an output ID
  res_output = get_output_response_new();
  if (res_output) {
    // get output metadata
    if (get_output_meta(&params->w->endpoint, params->output_id, res_output) != 0) {
      printf("[%s:%d] performed get_output_meta failed\n", __func__, __LINE__);
      items[CORE_GET_OUTPUTS_METADATA].st = STATE_NG;
      get_output_response_free(res_output);
      return -1;
    } else {
      if (res_output->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, res_output->u.error->msg);
        items[CORE_GET_OUTPUTS_METADATA].st = STATE_NG;
        get_output_response_free(res_output);
        return -1;
      } else {
        if (conf->show_payload) {
          dump_get_output_response(res_output, 0);
        }
        if (bin_2_hex(res_output->u.data->meta.tx_id, IOTA_TRANSACTION_ID_BYTES, NULL, params->tx_id,
                      sizeof(params->tx_id)) != 0) {
          printf("[%s:%d] convert transaction ID failed\n", __func__, __LINE__);
          items[CORE_GET_OUTPUTS_METADATA].st = STATE_NG;
        } else {
          printf("[%s:%d] GET /outputs/{outputId}/meta: PASS\n", __func__, __LINE__);
          items[CORE_GET_OUTPUTS_METADATA].st = STATE_PASS;
        }
      }
    }
  } else {
    printf("[%s:%d] allocate output response failed\n", __func__, __LINE__);
    return -1;
  }
  get_output_response_free(res_output);

  printf("Testing transaction ID: 0x%s\n", params->tx_id);
  // TODO: should be tested in Hornet alpha11
#if 0
  // transaction included block
  res_block_t* msg = res_block_new();
  if(msg){
    if(get_transaction_included_block_by_id(&params->w->endpoint, params->tx_id, msg) != 0){
      printf("[%s:%d] performed get_transaction_included_block_by_id failed\n", __func__, __LINE__);
      items[CORE_GET_TX_INC_MSG].st = STATE_NG;
      res_block_free(msg);
      return -1;
    }else{
      if(msg->is_error){
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, msg->u.error->msg);
        res_block_free(msg);
        return -1;
      }else{
        if(core_block_get_payload_type(msg->u.msg) == CORE_BLOCK_PAYLOAD_TRANSACTION){
          printf("[%s:%d] GET /transactions/{transactionId}/included-block: PASS\n", __func__, __LINE__);
      items[CORE_GET_TX_INC_MSG].st = STATE_PASS;
        }else{
          printf("[%s:%d] it's not a transaction payload\n", __func__, __LINE__);
      items[CORE_GET_TX_INC_MSG].st = STATE_NG;
          res_block_free(msg);
          return -1;
        }
      }
    }
  }else{
    printf("[%s:%d] allocate block response failed\n", __func__, __LINE__);
    return -1;
  }
#endif
  return 0;
}

int restful_api_tests(test_config_t* conf, test_data_t* params, test_item_t* items) {
  if (!conf || !params || !items) {
    printf("[%s:%d] invalid params\n", __func__, __LINE__);
    return -1;
  }

  int ret = 0;
  // try connect to the node
  if ((ret = get_info(conf, params, items)) != 0) {
    printf("[%s:%d] connecting to node failed\n", __func__, __LINE__);
    goto done;
  }

  // try connect to the node
  if ((ret = restful_get_tips(conf, params, items)) != 0) {
    printf("[%s:%d] get tips failed\n", __func__, __LINE__);
  }

  // wallet init
  if ((ret = init_wallet(conf, params, items)) != 0) {
    printf("[%s:%d] init wallet failed\n", __func__, __LINE__);
    goto done;
  }

  // request tokens for sender
  if ((ret = request_token(conf, params, items)) != 0) {
    printf("[%s:%d] request token from faucet failed\n", __func__, __LINE__);
  }

  // wait a little bit for getting tokens from faucet
  printf("[%s:%d] waiting for faucet...\n", __func__, __LINE__);
  sleep(conf->delay + 10);

  // send basic tx
  // get an valid block ID for blocks endpoints test
  if ((ret = send_basic_tx(conf, params, items)) != 0) {
    printf("[%s:%d] send basic tx failed\n", __func__, __LINE__);
    goto done;
  }

  // wait a little bit for block get confirmed
  printf("[%s:%d] waiting for block confirmation...\n", __func__, __LINE__);
  sleep(conf->delay);

  // send tagged block
  // get an valid block ID for blocks endpoints test
  if ((ret = send_tagged_payload(conf, params, items)) != 0) {
    printf("[%s:%d] send tagged block failed\n", __func__, __LINE__);
  }

  // wait a little bit for ledger status update
  printf("[%s:%d] waiting for ledger status update...\n", __func__, __LINE__);
  sleep(conf->delay);

  // fetch milestone
  if ((ret = fetch_milestone(conf, params, items)) != 0) {
    printf("[%s:%d] fetch milestone failed\n", __func__, __LINE__);
  }

  // validate blocks endpoints
  if ((ret = validating_blocks(conf, params, items)) != 0) {
    printf("[%s:%d] validate block endpoints failed\n", __func__, __LINE__);
  }

  // validate Indexer endpoints
  // get the testing output ID from indexer for validating UTXO endpoints
  if ((ret = validating_indexers_basic(conf, params, items)) != 0) {
    printf("[%s:%d] validate basic indexer endpoints failed\n", __func__, __LINE__);
  }

  // validate UTXO endpoints
  if ((ret = validating_utxo(conf, params, items)) != 0) {
    printf("[%s:%d] validate UTXO endpoints failed\n", __func__, __LINE__);
  }

done:
  return ret;
}
