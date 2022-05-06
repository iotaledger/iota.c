// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>  // for Linux sleep()

#include "client/api/restful/faucet_enqueue.h"
#include "client/api/restful/get_message.h"
#include "client/api/restful/get_message_children.h"
#include "client/api/restful/get_message_metadata.h"
#include "client/api/restful/get_milestone.h"
#include "client/api/restful/get_node_info.h"
#include "client/api/restful/get_output.h"
#include "client/api/restful/get_outputs_id.h"
#include "client/api/restful/get_transaction_included_message.h"
#include "client/api/restful/send_tagged_data.h"
#include "functional_cases.h"

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
        printf("[%s:%d] GET /api/v2/info: PASS\n", __func__, __LINE__);
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

static int init_wallet(test_config_t* conf, test_data_t* params, test_item_t* items) {
  if (!conf || !params || !items) {
    printf("[%s:%d] invalid params\n", __func__, __LINE__);
    return -1;
  }

  int ret = 0;
  params->w = wallet_create(conf->mnemonic, "", 0);
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

  // validating /api/v2/info
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
  char sender_bech32[BIN_TO_HEX_STR_BYTES(ADDRESS_MAX_BYTES)] = {};

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
  res_send_message_t msg_res = {};

  ret = wallet_ed25519_address_from_index(params->w, false, conf->receiver_index, &params->recv);
  if (ret != 0) {
    printf("[%s:%d] derive receiver address failed\n", __func__, __LINE__);
    return -1;
  }

  // validating /api/v2/tips and /api/v2/message with basic outputs
  // send 1Mi to receiver
  printf("Basic sender: ");
  address_print(&params->sender);
  printf("Basic receiver: ");
  address_print(&params->recv);
  ret = wallet_send_basic_outputs(params->w, false, conf->sender_index, &params->recv, 1000000, &msg_res);
  if (ret == 0) {
    if (msg_res.is_error) {
      printf("[%s:%d] Error: %s\n", __func__, __LINE__, msg_res.u.error->msg);
      res_err_free(msg_res.u.error);
      items[CORE_POST_BASIC_MSG].st = STATE_NG;
      return -1;
    } else {
      strncpy(params->basic_msg_id, msg_res.u.msg_id, BIN_TO_HEX_STR_BYTES(IOTA_MESSAGE_ID_BYTES));
      printf("[%s:%d] Basic Message ID: %s\n", __func__, __LINE__, msg_res.u.msg_id);
      printf("[%s:%d] GET /api/v2/tips: PASS\n", __func__, __LINE__);
      printf("[%s:%d] POST /api/v2/message: PASS\n", __func__, __LINE__);
      items[CORE_GET_TIPS].st = STATE_PASS;
      items[CORE_POST_BASIC_MSG].st = STATE_PASS;
    }
  } else {
    printf("[%s:%d] send message failed\n", __func__, __LINE__);
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
  res_send_message_t res = {};
  byte_t tag[8];
  iota_crypto_randombytes(tag, 8);
  byte_t tag_data[64];
  iota_crypto_randombytes(tag_data, 64);

  ret = send_tagged_data_message(&params->w->endpoint, params->w->protocol_version, tag, sizeof(tag), tag_data,
                                 sizeof(tag_data), &res);
  if (ret == 0) {
    if (res.is_error) {
      printf("[%s:%d]Err: %s\n", __func__, __LINE__, res.u.error->msg);
      res_err_free(res.u.error);
      items[CORE_POST_TAGGED_MSG].st = STATE_NG;
      return -1;
    } else {
      strncpy(params->tagged_msg_id, res.u.msg_id, BIN_TO_HEX_STR_BYTES(IOTA_MESSAGE_ID_BYTES));
      printf("[%s:%d] Tagged Message ID: %s\n", __func__, __LINE__, res.u.msg_id);
      items[CORE_POST_TAGGED_MSG].st = STATE_PASS;
    }
  } else {
    printf("[%s:%d] performed send_tagged_data_message failed\n", __func__, __LINE__);
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

  // validatin /api/v2/milestones/by-index/{index}
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
                  params->milestone_msg_id, sizeof(params->milestone_msg_id));
        printf("[%s:%d] Milestone ID: %s\n", __func__, __LINE__, params->milestone_msg_id);
        printf("[%s:%d] GET /api/v2/milestones/by-index/{index}: PASS\n", __func__, __LINE__);
        items[CORE_GET_MILESTONES_INDEX].st = STATE_PASS;
      }
    } else {
      printf("[%s:%d] performed send_tagged_data_message failed\n", __func__, __LINE__);
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

  // validatin /api/v2/milestones/{milestoneId}
  byte_t empty_milstone_id[IOTA_MESSAGE_ID_BYTES] = {};
  res_ml = res_milestone_new();
  if (res_ml) {
    // get milestone by ID
    ret = get_milestone_by_id(&params->w->endpoint, params->milestone_msg_id, res_ml);
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
          printf("[%s:%d] GET /api/v2/milestones/{milestoneId}: PASS\n", __func__, __LINE__);
          items[CORE_GET_MILESTONES].st = STATE_PASS;
        } else {
          printf("[%s:%d] previous_milestone_id is not expected\n", __func__, __LINE__);
          items[CORE_GET_MILESTONES].st = STATE_NG;
          res_milestone_free(res_ml);
          return -1;
        }
      }
    } else {
      printf("[%s:%d] perfrome get_milestone_by_id failed\n", __func__, __LINE__);
      items[CORE_GET_MILESTONES].st = STATE_NG;
      res_milestone_free(res_ml);
      return -1;
    }
  } else {
    printf("[%s:%d] allocate milestone response failed\n", __func__, __LINE__);
    return -1;
  }
  res_milestone_free(res_ml);

  // validatin /api/v2/milestones/by-index/{index}/utxo_changes
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
        printf("[%s:%d] GET /api/v2/milestones/by-index/{index}/utxo_changes: PASS\n", __func__, __LINE__);
        items[CORE_GET_MILESTONES_INDEX_UTXO].st = STATE_PASS;
      }
    } else {
      printf("[%s:%d] perfrome get_utxo_changes_by_ms_index failed\n", __func__, __LINE__);
      items[CORE_GET_MILESTONES_INDEX_UTXO].st = STATE_NG;
      res_milestone_free(res_ml);
      return -1;
    }
  } else {
    printf("[%s:%d] allocate milestone utxo response failed\n", __func__, __LINE__);
    return -1;
  }
  res_utxo_changes_free(res_ml_utxo);
  res_ml_utxo = NULL;

  // validatin /api/v2/milestones/{milestoneId}/utxo_changes
  res_ml_utxo = res_utxo_changes_new();
  if (res_ml_utxo) {
    ret = get_utxo_changes_by_ms_id(&params->w->endpoint, params->milestone_msg_id, res_ml_utxo);
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
        printf("[%s:%d] GET /api/v2/milestones/{milestoneId}/utxo_changes: PASS\n", __func__, __LINE__);
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

static int validating_messages(test_config_t* conf, test_data_t* params, test_item_t* items) {
  if (!conf || !params || !items) {
    printf("[%s:%d] invalid params\n", __func__, __LINE__);
    return -1;
  }

  int ret = 0;
  printf("Test Message IDs:\n");
  printf("Basic: 0x%s\n", params->basic_msg_id);
  printf("Milestone: 0x%s\n", params->milestone_msg_id);
  printf("Tagged Data: 0x%s\n", params->tagged_msg_id);

  // validating /api/v2/messages/{messageId}
  // Basic outputs
  res_message_t* msg_from_id = res_message_new();
  if (msg_from_id) {
    ret = get_message_by_id(&params->w->endpoint, params->basic_msg_id, msg_from_id);
    if (ret == 0) {
      if (msg_from_id->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, msg_from_id->u.error->msg);
        res_message_free(msg_from_id);
        items[CORE_GET_MSG_BASIC].st = STATE_NG;
        return -1;
      } else {
        if (conf->show_payload) {
          core_message_print(msg_from_id->u.msg, 0);
        }
        items[CORE_GET_MSG_BASIC].st = STATE_PASS;
        printf("[%s:%d] GET /api/v2/messages/{messageId}: Basic Outputs PASS\n", __func__, __LINE__);
      }
    } else {
      printf("[%s:%d] performed get_message_by_id failed\n", __func__, __LINE__);
      items[CORE_GET_MSG_BASIC].st = STATE_NG;
      res_message_free(msg_from_id);
      return ret;
    }
  } else {
    printf("[%s:%d] allocate message response failed\n", __func__, __LINE__);
    return -1;
  }
  res_message_free(msg_from_id);
  msg_from_id = NULL;

  // Milestone
  msg_from_id = res_message_new();
  if (msg_from_id) {
    ret = get_message_by_id(&params->w->endpoint, params->milestone_msg_id, msg_from_id);
    if (ret == 0) {
      // milestone ID is not a message
      if (msg_from_id->is_error) {
        printf("[%s:%d] GET /api/v2/messages/{messageId}: Milestone PASS\n", __func__, __LINE__);
        items[CORE_GET_MSG_MILESTONE].st = STATE_PASS;
      } else {
        printf("[%s:%d] GET /api/v2/messages/{messageId}: Milestone NG\n", __func__, __LINE__);
        res_message_free(msg_from_id);
        items[CORE_GET_MSG_MILESTONE].st = STATE_NG;
        return -1;
      }
    } else {
      printf("[%s:%d] performed get_message_by_id failed\n", __func__, __LINE__);
      items[CORE_GET_MSG_MILESTONE].st = STATE_NG;
      res_message_free(msg_from_id);
      return ret;
    }
  } else {
    printf("[%s:%d] allocate message response failed\n", __func__, __LINE__);
    return -1;
  }
  res_message_free(msg_from_id);
  msg_from_id = NULL;

  // Tagged message
  msg_from_id = res_message_new();
  if (msg_from_id) {
    ret = get_message_by_id(&params->w->endpoint, params->tagged_msg_id, msg_from_id);
    if (ret == 0) {
      if (msg_from_id->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, msg_from_id->u.error->msg);
        res_message_free(msg_from_id);
        items[CORE_GET_MSG_TAGGED].st = STATE_NG;
        return -1;
      } else {
        if (conf->show_payload) {
          core_message_print(msg_from_id->u.msg, 0);
        }
        printf("[%s:%d] GET /api/v2/messages/{messageId}: Tagged Data PASS\n", __func__, __LINE__);
        items[CORE_GET_MSG_TAGGED].st = STATE_PASS;
      }
    } else {
      printf("[%s:%d] performed get_message_by_id failed\n", __func__, __LINE__);
      res_message_free(msg_from_id);
      items[CORE_GET_MSG_TAGGED].st = STATE_NG;
      return ret;
    }
  } else {
    printf("[%s:%d] allocate message response failed\n", __func__, __LINE__);
    return -1;
  }
  res_message_free(msg_from_id);

  // validating /api/v2/messages/{messageId}/metadata
  res_msg_meta_t* meta = msg_meta_new();
  if (meta) {
    ret = get_message_metadata(&params->w->endpoint, params->basic_msg_id, meta);
    if (ret == 0) {
      if (meta->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, meta->u.error->msg);
        items[CORE_GET_MSG_META_BASIC].st = STATE_NG;
        msg_meta_free(meta);
        return -1;
      } else {
        if (conf->show_payload) {
          print_message_metadata(meta, 0);
        }
        printf("[%s:%d] GET /api/v2/messages/{messageId}/metadata: Basic Outputs PASS\n", __func__, __LINE__);
        items[CORE_GET_MSG_META_BASIC].st = STATE_PASS;
      }
    } else {
      printf("[%s:%d] performed get_message_metadata failed\n", __func__, __LINE__);
      items[CORE_GET_MSG_META_BASIC].st = STATE_NG;
      msg_meta_free(meta);
      return ret;
    }
  } else {
    printf("[%s:%d] allocate message metadata response failed\n", __func__, __LINE__);
    return -1;
  }
  msg_meta_free(meta);
  meta = NULL;
  // Milestone
  meta = msg_meta_new();
  if (meta) {
    ret = get_message_metadata(&params->w->endpoint, params->milestone_msg_id, meta);
    if (ret == 0) {
      // milestone ID is not a message
      if (meta->is_error) {
        printf("[%s:%d] GET /api/v2/messages/{messageId}/metadata: Milestone PASS\n", __func__, __LINE__);
        items[CORE_GET_MSG_META_MILESTONE].st = STATE_PASS;
      } else {
        printf("[%s:%d] GET /api/v2/messages/{messageId}/metadata: Milestone NG\n", __func__, __LINE__);
        items[CORE_GET_MSG_META_MILESTONE].st = STATE_NG;
        msg_meta_free(meta);
        return -1;
      }
    } else {
      printf("[%s:%d] performed get_message_metadata failed\n", __func__, __LINE__);
      items[CORE_GET_MSG_META_MILESTONE].st = STATE_NG;
      msg_meta_free(meta);
      return ret;
    }
  } else {
    printf("[%s:%d] allocate message metadata response failed\n", __func__, __LINE__);
    return -1;
  }
  msg_meta_free(meta);
  meta = NULL;
  // Tagged data
  meta = msg_meta_new();
  if (meta) {
    ret = get_message_metadata(&params->w->endpoint, params->tagged_msg_id, meta);
    if (ret == 0) {
      if (meta->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, meta->u.error->msg);
        items[CORE_GET_MSG_META_TAGGED].st = STATE_NG;
        msg_meta_free(meta);
        return -1;
      } else {
        if (conf->show_payload) {
          print_message_metadata(meta, 0);
        }
        printf("[%s:%d] GET /api/v2/messages/{messageId}/metadata: Tagged Data PASS\n", __func__, __LINE__);
        items[CORE_GET_MSG_META_TAGGED].st = STATE_PASS;
      }
    } else {
      printf("[%s:%d] performed get_message_metadata failed\n", __func__, __LINE__);
      items[CORE_GET_MSG_META_TAGGED].st = STATE_NG;
      msg_meta_free(meta);
      return ret;
    }
  } else {
    printf("[%s:%d] allocate message metadata response failed\n", __func__, __LINE__);
    return -1;
  }
  msg_meta_free(meta);

  // validating /api/v2/messages/{messageId}/children
  res_msg_children_t* msg_child = res_msg_children_new();
  if (msg_child) {
    ret = get_message_children(&params->w->endpoint, params->basic_msg_id, msg_child);
    if (ret == 0) {
      if (msg_child->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, msg_child->u.error->msg);
        res_msg_children_free(msg_child);
        items[CORE_GET_MSG_CHILD_BASIC].st = STATE_NG;
        return -1;
      } else {
        if (conf->show_payload) {
          print_message_children(msg_child, 0);
        }
        printf("[%s:%d] GET /api/v2/messages/{messageId}/children: Basic Outputs PASS\n", __func__, __LINE__);
        items[CORE_GET_MSG_CHILD_BASIC].st = STATE_PASS;
      }
    } else {
      printf("[%s:%d] performed get_message_children failed\n", __func__, __LINE__);
      items[CORE_GET_MSG_CHILD_BASIC].st = STATE_NG;
      res_msg_children_free(msg_child);
      return ret;
    }
  } else {
    printf("[%s:%d] allocate message children response failed\n", __func__, __LINE__);
    return -1;
  }
  res_msg_children_free(msg_child);
  msg_child = NULL;
  // Milestone
  msg_child = res_msg_children_new();
  if (msg_child) {
    ret = get_message_children(&params->w->endpoint, params->milestone_msg_id, msg_child);
    if (ret == 0) {
      // milestone is not a message
      if (msg_child->is_error) {
        printf("[%s:%d] GET /api/v2/messages/{messageId}/children: Milestone PASS\n", __func__, __LINE__);
        items[CORE_GET_MSG_CHILD_MILESTONE].st = STATE_PASS;
      } else {
        // TODO, fix hornet#1488
        printf("[%s:%d] GET /api/v2/messages/{messageId}/children: Milestone NG\n", __func__, __LINE__);
        printf("[%s:%d] https://github.com/gohornet/hornet/issues/1488\n", __func__, __LINE__);
        items[CORE_GET_MSG_CHILD_MILESTONE].st = STATE_NG;
        // res_msg_children_free(msg_child);
        // return -1;
      }
    } else {
      printf("[%s:%d] performed get_message_children failed\n", __func__, __LINE__);
      items[CORE_GET_MSG_CHILD_MILESTONE].st = STATE_NG;
      res_msg_children_free(msg_child);
      return ret;
    }
  } else {
    printf("[%s:%d] allocate message children response failed\n", __func__, __LINE__);
    return -1;
  }
  res_msg_children_free(msg_child);
  msg_child = NULL;
  // Tagged Data
  msg_child = res_msg_children_new();
  if (msg_child) {
    ret = get_message_children(&params->w->endpoint, params->tagged_msg_id, msg_child);
    if (ret == 0) {
      if (msg_child->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, msg_child->u.error->msg);
        items[CORE_GET_MSG_CHILD_TAGGED].st = STATE_NG;
        res_msg_children_free(msg_child);
        return -1;
      } else {
        if (conf->show_payload) {
          print_message_children(msg_child, 0);
        }
        printf("[%s:%d] GET /api/v2/messages/{messageId}/children: Tagged Data PASS\n", __func__, __LINE__);
        items[CORE_GET_MSG_CHILD_TAGGED].st = STATE_PASS;
      }
    } else {
      printf("[%s:%d] performed get_message_children failed\n", __func__, __LINE__);
      items[CORE_GET_MSG_CHILD_TAGGED].st = STATE_NG;
      res_msg_children_free(msg_child);
      return ret;
    }
  } else {
    printf("[%s:%d] allocate message children response failed\n", __func__, __LINE__);
    return -1;
  }
  res_msg_children_free(msg_child);

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
  char bech32_addr[BIN_TO_HEX_STR_BYTES(ADDRESS_MAX_BYTES)] = {};
  if (address_to_bech32(&params->sender, params->w->bech32HRP, bech32_addr, sizeof(bech32_addr)) != 0) {
    printf("[%s:%d] convert sender address to bech32 address failed\n", __func__, __LINE__);
    return -1;
  }

  // prepare query filter
  outputs_query_list_t* filter = outputs_query_list_new();
  // add query paramters
  if (outputs_query_list_add(&filter, QUERY_PARAM_ADDRESS, bech32_addr) != 0) {
    printf("[%s:%d] add query paramter failed\n", __func__, __LINE__);
    outputs_query_list_free(filter);
    return -1;
  }

  // query output IDs
  res_ids = res_outputs_new();
  if (res_ids) {
    ret = get_outputs_id(&params->w->endpoint, filter, res_ids);
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
      printf("[%s:%d] performed get_outputs_id failed\n", __func__, __LINE__);
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
  printf("Testing output ID: 0x%s\n", params->basic_msg_id);

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
        printf("[%s:%d] GET /api/v2/outputs/{outputId}: PASS\n", __func__, __LINE__);
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
          printf("[%s:%d] GET /api/v2/outputs/{outputId}/meta: PASS\n", __func__, __LINE__);
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
  // TODO: should be tested after hoenet alpha11
#if 0
  // transaction included message
  res_message_t* msg = res_message_new();
  if(msg){
    if(get_transaction_included_message_by_id(&params->w->endpoint, params->tx_id, msg) != 0){
      printf("[%s:%d] performed get_transaction_included_message_by_id failed\n", __func__, __LINE__);
      items[CORE_GET_TX_INC_MSG].st = STATE_NG;
      res_message_free(msg);
      return -1;
    }else{
      if(msg->is_error){
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, msg->u.error->msg);
        res_message_free(msg);
        return -1;
      }else{
        if(core_message_get_payload_type(msg->u.msg) == CORE_MESSAGE_PAYLOAD_TRANSACTION){
          printf("[%s:%d] GET /api/v2/transactions/{transactionId}/included-message: PASS\n", __func__, __LINE__);
      items[CORE_GET_TX_INC_MSG].st = STATE_PASS;
        }else{
          printf("[%s:%d] it's not a transaction payload\n", __func__, __LINE__);
      items[CORE_GET_TX_INC_MSG].st = STATE_NG;
          res_message_free(msg);
          return -1;
        }
      }
    }
  }else{
    printf("[%s:%d] allocate message response failed\n", __func__, __LINE__);
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

  // wallet init
  if ((ret = init_wallet(conf, params, items)) != 0) {
    printf("[%s:%d] init wallet failed\n", __func__, __LINE__);
    goto done;
  }

  // request tokens for sender
  if ((ret = request_token(conf, params, items)) != 0) {
    printf("[%s:%d] request token from faucet failed\n", __func__, __LINE__);
    goto done;
  }

  // wait a little bit for getting tokens from faucet
  printf("[%s:%d] waiting for faucet...\n", __func__, __LINE__);
  sleep(conf->delay + 10);

  // send basic tx
  // get an valid message ID for messages endpoints test
  if ((ret = send_basic_tx(conf, params, items)) != 0) {
    printf("[%s:%d] send basic tx failed\n", __func__, __LINE__);
    goto done;
  }

  // wait a little bit for message get confirmed
  printf("[%s:%d] waiting for message confirmation...\n", __func__, __LINE__);
  sleep(conf->delay);

  // send tagged message
  // get an valid message ID for messages endpoints test
  if ((ret = send_tagged_payload(conf, params, items)) != 0) {
    printf("[%s:%d] send tagged message failed\n", __func__, __LINE__);
    goto done;
  }

  // wait a little bit for ledger status update
  printf("[%s:%d] waiting for ledger status update...\n", __func__, __LINE__);
  sleep(conf->delay);

  // fetch milestone
  if ((ret = fetch_milestone(conf, params, items)) != 0) {
    printf("[%s:%d] fetch milestone failed\n", __func__, __LINE__);
    goto done;
  }

  // validate messages endpoints
  if ((ret = validating_messages(conf, params, items)) != 0) {
    printf("[%s:%d] validate message endpoints failed\n", __func__, __LINE__);
    goto done;
  }

  // validate Indexer endpoints
  // get the testing output ID from indexer for validating UTXO endpoints
  if ((ret = validating_indexers_basic(conf, params, items)) != 0) {
    printf("[%s:%d] validate basic indexer endpoints failed\n", __func__, __LINE__);
    goto done;
  }

  // validate UTXO endpoints
  if ((ret = validating_utxo(conf, params, items)) != 0) {
    printf("[%s:%d] validate UTXO endpoints failed\n", __func__, __LINE__);
    goto done;
  }

done:
  return ret;
}
