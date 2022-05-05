#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  // for Linux sleep()

#include "client/api/json_parser/json_utils.h"
#include "client/api/restful/faucet_enqueue.h"
#include "client/api/restful/get_message.h"
#include "client/api/restful/get_message_children.h"
#include "client/api/restful/get_message_metadata.h"
#include "client/api/restful/get_milestone.h"
#include "client/api/restful/get_node_info.h"
#include "client/api/restful/get_output.h"
#include "client/api/restful/get_outputs_id.h"
#include "client/api/restful/get_transaction_included_message.h"
#include "client/api/restful/response_error.h"
#include "client/api/restful/send_tagged_data.h"
#include "client/client_service.h"
#include "core/address.h"
#include "core/models/message.h"
#include "core/models/payloads/milestone.h"
#include "core/utils/byte_buffer.h"
#include "core/utils/macros.h"
#include "wallet/wallet.h"

typedef struct {
  char mnemonic[512];
  uint32_t sender_index;
  uint32_t receiver_index;
  iota_client_conf_t node_config;    ///< node config
  iota_client_conf_t faucet_config;  ///< faucet config
  bool show_payload;                 ///< True for showing message payloads
  uint16_t delay;                    ///< delay time for checking transaction in secondes
} test_config_t;

typedef struct {
  address_t sender;
  address_t recv;
  char basic_msg_id[BIN_TO_HEX_STR_BYTES(IOTA_MESSAGE_ID_BYTES)];
  char milestone_msg_id[BIN_TO_HEX_STR_BYTES(IOTA_MESSAGE_ID_BYTES)];
  char tagged_msg_id[BIN_TO_HEX_STR_BYTES(IOTA_MESSAGE_ID_BYTES)];
  char output_id[BIN_TO_HEX_STR_BYTES(IOTA_OUTPUT_ID_BYTES)];
  char tx_id[BIN_TO_HEX_STR_BYTES(IOTA_TRANSACTION_ID_BYTES)];
  iota_wallet_t* w;
} test_data_t;

// paramters and settings for functional test
test_data_t g_params;
test_config_t g_config;

static void dump_test_config(test_config_t* config) {
  printf("=========Test Config==========\n");
  printf("Mnemonic: %s\n", config->mnemonic);
  printf("Sender Address Index: %u\n", config->sender_index);
  printf("Receiver Address Index: %u\n", config->receiver_index);
  printf("Node: %s:%d tls: %s\n", config->node_config.host, config->node_config.port,
         config->node_config.use_tls ? "true" : "false");
  printf("Faucet: %s:%d tls: %s\n", config->faucet_config.host, config->faucet_config.port,
         config->faucet_config.use_tls ? "true" : "false");
  printf("Show paylaod: %s\n", config->show_payload ? "true" : "false");
  printf("Delay: %d\n", config->delay);
  printf("==============================\n");
}

static int parse_config(char* const config_data) {
  int ret = 0;
  // init config object
  memset(&g_config, 0, sizeof(test_config_t));

  cJSON* config_obj = cJSON_Parse(config_data);
  if (config_obj == NULL) {
    printf("[%s:%d] invalid JSON object", __func__, __LINE__);
    return -1;
  }

  // mnemonic
  if ((ret = json_get_string(config_obj, "mnemonic", g_config.mnemonic, sizeof(g_config.mnemonic))) != 0) {
    printf("[%s:%d] get mnemonic object failed\n", __func__, __LINE__);
    goto end;
  }

  // address index of sender
  if ((ret = json_get_uint32(config_obj, "sender_index", &g_config.sender_index)) != 0) {
    printf("[%s:%d] get sender address index failed\n", __func__, __LINE__);
    goto end;
  }

  // address index of receiver
  if ((ret = json_get_uint32(config_obj, "receiver_index", &g_config.sender_index)) != 0) {
    printf("[%s:%d] get receiver address index failed\n", __func__, __LINE__);
    goto end;
  }

  // node host
  if ((ret = json_get_string(config_obj, "node", g_config.node_config.host, sizeof(g_config.node_config.host))) != 0) {
    printf("[%s:%d] get host object failed\n", __func__, __LINE__);
    goto end;
  }
  // node port
  if ((ret = json_get_uint16(config_obj, "port", &g_config.node_config.port)) != 0) {
    printf("[%s:%d] get port object failed\n", __func__, __LINE__);
    goto end;
  }
  // TLS support
  if ((ret = json_get_boolean(config_obj, "use_tls", &g_config.node_config.use_tls)) != 0) {
    printf("[%s:%d] get TLS object failed\n", __func__, __LINE__);
    goto end;
  }

  // faucet host
  if ((ret = json_get_string(config_obj, "faucet", g_config.faucet_config.host, sizeof(g_config.faucet_config.host))) !=
      0) {
    printf("[%s:%d] get faucet host object failed\n", __func__, __LINE__);
    goto end;
  }
  // faucet port
  if ((ret = json_get_uint16(config_obj, "faucet_port", &g_config.faucet_config.port)) != 0) {
    printf("[%s:%d] get faucet port object failed\n", __func__, __LINE__);
    goto end;
  }
  // faucet TLS support
  if ((ret = json_get_boolean(config_obj, "faucet_use_tls", &g_config.faucet_config.use_tls)) != 0) {
    printf("[%s:%d] get faucet TLS object failed\n", __func__, __LINE__);
    goto end;
  }

  // display payload on terminal
  if ((ret = json_get_boolean(config_obj, "show_payload", &g_config.show_payload)) != 0) {
    printf("[%s:%d] get show_payload object failed\n", __func__, __LINE__);
    goto end;
  }

  // delay
  if ((ret = json_get_uint16(config_obj, "delay", &g_config.delay)) != 0) {
    printf("[%s:%d] get delay object failed\n", __func__, __LINE__);
  }

end:
  cJSON_Delete(config_obj);
  return ret;
}

static int read_config_file(char const* const config) {
  FILE* fp = fopen(config, "r");
  char* file_buf = NULL;
  if (fp) {
    // get file size
    long f_size = 0;
    if (fseek(fp, 0, SEEK_END) == 0) {
      f_size = ftell(fp);
      rewind(fp);
    } else {
      printf("[%s:%d] get file size error\n", __func__, __LINE__);
      fclose(fp);
      return -1;
    }

    // allocate buffer
    file_buf = malloc(f_size + 1);
    if (file_buf) {
      // read config file
      fread(file_buf, 1, f_size, fp);
      file_buf[f_size] = '\0';
    } else {
      printf("[%s:%d] allocate buffer error\n", __func__, __LINE__);
      fclose(fp);
      return -1;
    }
    fclose(fp);
  } else {
    printf("[%s:%d] cannot open file: %s\n", __func__, __LINE__, config);
  }

  // parsing config file
  if (parse_config(file_buf)) {
    printf("[%s:%d] parsing config data failed\n", __func__, __LINE__);
    free(file_buf);
    return -1;
  }

  if (g_config.show_payload) {
    dump_test_config(&g_config);
  }

  free(file_buf);
  return 0;
}
static int get_info() {
  res_node_info_t* info = res_node_info_new();
  if (info) {
    int ret = get_node_info(&g_config.node_config, info);
    if (ret == 0) {
      if (info->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, info->u.error->msg);
      } else {
        if (g_config.show_payload) {
          node_info_print(info, 0);
        }
        printf("[%s:%d] GET /api/v2/info: PASS\n", __func__, __LINE__);
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

static int init_wallet() {
  int ret = 0;
  g_params.w = wallet_create(g_config.mnemonic, "", 0);
  if (!g_params.w) {
    printf("[%s:%d] wallet create failed\n", __func__, __LINE__);
    return -1;
  }

  ret = wallet_set_endpoint(g_params.w, g_config.node_config.host, g_config.node_config.port,
                            g_config.node_config.use_tls);
  if (ret != 0) {
    printf("[%s:%d] wallet set endpoint failed\n", __func__, __LINE__);
    wallet_destroy(g_params.w);
    return -1;
  }

  // validating /api/v2/info
  ret = wallet_update_node_config(g_params.w);
  if (ret != 0) {
    printf("[%s:%d] wallet get node info failed\n", __func__, __LINE__);
    wallet_destroy(g_params.w);
    return -1;
  }
  return 0;
}

static int request_token() {
  int ret = 0;
  res_faucet_enqueue_t res = {};
  char sender_bech32[BIN_TO_HEX_STR_BYTES(ADDRESS_MAX_BYTES)] = {};

  ret = wallet_ed25519_address_from_index(g_params.w, false, g_config.sender_index, &g_params.sender);
  if (ret != 0) {
    printf("[%s:%d] derive sender address failed\n", __func__, __LINE__);
    return -1;
  }

  ret = address_to_bech32(&g_params.sender, g_params.w->bech32HRP, sender_bech32, sizeof(sender_bech32));
  if (ret != 0) {
    printf("[%s:%d] get bech32 address failed\n", __func__, __LINE__);
    return -1;
  }

  // Test bech32 address with invalid len
  ret = req_tokens_to_addr_from_faucet(&g_config.faucet_config, sender_bech32, &res);
  if (ret == 0) {
    if (res.is_error == true) {
      if (strstr(res.u.error->msg, "have enough funds")) {
        printf("[%s:%d] POST faucet enqueue: PASS - have enough funds\n", __func__, __LINE__);
        res_err_free(res.u.error);
      } else {
        printf("[%s:%d] request token err: %s\n", __func__, __LINE__, res.u.error->msg);
        res_err_free(res.u.error);
        return -1;
      }
    } else {
      printf("request token: %s\n", sender_bech32);
      printf("[%s:%d] POST faucet enqueue: PASS\n", __func__, __LINE__);
    }
  }
  return ret;
}

static int send_basic_tx() {
  int ret = 0;
  res_send_message_t msg_res = {};

  ret = wallet_ed25519_address_from_index(g_params.w, false, g_config.receiver_index, &g_params.recv);
  if (ret != 0) {
    printf("[%s:%d] derive receiver address failed\n", __func__, __LINE__);
    return -1;
  }

  // validating /api/v2/tips and /api/v2/message with basic outputs
  // send 1Mi to receiver
  printf("Basic sender: ");
  address_print(&g_params.sender);
  printf("Basic receiver: ");
  address_print(&g_params.recv);
  ret = wallet_send_basic_outputs(g_params.w, false, g_config.sender_index, &g_params.recv, 1000000, &msg_res);
  if (ret == 0) {
    if (msg_res.is_error) {
      printf("[%s:%d] Error: %s\n", __func__, __LINE__, msg_res.u.error->msg);
      res_err_free(msg_res.u.error);
      return -1;
    } else {
      strncpy(g_params.basic_msg_id, msg_res.u.msg_id, BIN_TO_HEX_STR_BYTES(IOTA_MESSAGE_ID_BYTES));
      printf("[%s:%d] Basic Message ID: %s\n", __func__, __LINE__, msg_res.u.msg_id);
      printf("[%s:%d] GET /api/v2/tips: PASS\n", __func__, __LINE__);
      printf("[%s:%d] POST /api/v2/message: PASS\n", __func__, __LINE__);
    }
  } else {
    printf("[%s:%d] send message failed\n", __func__, __LINE__);
    return -1;
  }
  return 0;
}

static int send_tagged_payload() {
  int ret = 0;
  res_send_message_t res = {};
  byte_t tag[8];
  iota_crypto_randombytes(tag, 8);
  byte_t tag_data[64];
  iota_crypto_randombytes(tag_data, 64);

  ret = send_tagged_data_message(&g_params.w->endpoint, g_params.w->protocol_version, tag, sizeof(tag), tag_data,
                                 sizeof(tag_data), &res);
  if (ret == 0) {
    if (res.is_error) {
      printf("[%s:%d]Err: %s\n", __func__, __LINE__, res.u.error->msg);
      res_err_free(res.u.error);
      return -1;
    } else {
      strncpy(g_params.tagged_msg_id, res.u.msg_id, BIN_TO_HEX_STR_BYTES(IOTA_MESSAGE_ID_BYTES));
      printf("[%s:%d] Tagged Message ID: %s\n", __func__, __LINE__, res.u.msg_id);
    }
  } else {
    printf("[%s:%d] performed send_tagged_data_message failed\n", __func__, __LINE__);
  }
  return 0;
}

static int fetch_milestone() {
  int ret = 0;

  // validatin /api/v2/milestones/by-index/{index}
  res_milestone_t* res_ml = res_milestone_new();
  if (res_ml) {
    // get milestone of index 2
    ret = get_milestone_by_index(&g_params.w->endpoint, 2, res_ml);
    if (ret == 0) {
      if (res_ml->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, res_ml->u.error->msg);
        res_milestone_free(res_ml);
        return -1;
      } else {
        if (g_config.show_payload) {
          milestone_payload_print(res_ml->u.ms, 0);
        }
        bin_2_hex(res_ml->u.ms->previous_milestone_id, sizeof(res_ml->u.ms->previous_milestone_id), NULL,
                  g_params.milestone_msg_id, sizeof(g_params.milestone_msg_id));
        printf("[%s:%d] Milestone ID: %s\n", __func__, __LINE__, g_params.milestone_msg_id);
        printf("[%s:%d] GET /api/v2/milestones/by-index/{index}: PASS\n", __func__, __LINE__);
      }
    } else {
      printf("[%s:%d] performed send_tagged_data_message failed\n", __func__, __LINE__);
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
    ret = get_milestone_by_id(&g_params.w->endpoint, g_params.milestone_msg_id, res_ml);
    if (ret == 0) {
      if (res_ml->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, res_ml->u.error->msg);
        res_milestone_free(res_ml);
        return -1;
      } else {
        if (g_config.show_payload) {
          milestone_payload_print(res_ml->u.ms, 0);
        }
        // the previous_milestone_id should be empty since we are query milestone index 1
        if (memcmp(empty_milstone_id, res_ml->u.ms->previous_milestone_id, sizeof(empty_milstone_id)) == 0) {
          printf("[%s:%d] GET /api/v2/milestones/{milestoneId}: PASS\n", __func__, __LINE__);
        } else {
          printf("[%s:%d] \n", __func__, __LINE__);
          res_milestone_free(res_ml);
          return -1;
        }
      }
    } else {
      printf("[%s:%d] perfrome send_tagged_data_message failed\n", __func__, __LINE__);
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
    ret = get_utxo_changes_by_ms_index(&g_params.w->endpoint, 2, res_ml_utxo);
    if (ret == 0) {
      if (res_ml_utxo->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, res_ml_utxo->u.error->msg);
        res_utxo_changes_free(res_ml_utxo);
        return -1;
      } else {
        if (g_config.show_payload) {
          print_utxo_changes(res_ml_utxo, 0);
        }
        printf("[%s:%d] GET /api/v2/milestones/by-index/{index}/utxo_changes: PASS\n", __func__, __LINE__);
      }
    } else {
      printf("[%s:%d] perfrome send_tagged_data_message failed\n", __func__, __LINE__);
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
    ret = get_utxo_changes_by_ms_id(&g_params.w->endpoint, g_params.milestone_msg_id, res_ml_utxo);
    if (ret == 0) {
      if (res_ml_utxo->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, res_ml_utxo->u.error->msg);
        res_utxo_changes_free(res_ml_utxo);
        return -1;
      } else {
        if (g_config.show_payload) {
          print_utxo_changes(res_ml_utxo, 0);
        }
        printf("[%s:%d] GET /api/v2/milestones/{milestoneId}/utxo_changes: PASS\n", __func__, __LINE__);
      }
    } else {
      printf("[%s:%d] performed send_tagged_data_message failed\n", __func__, __LINE__);
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

static int validating_messages(iota_wallet_t* w) {
  int ret = 0;
  printf("Test Message IDs:\n");
  printf("Basic: 0x%s\n", g_params.basic_msg_id);
  printf("Milestone: 0x%s\n", g_params.milestone_msg_id);
  printf("Tagged Data: 0x%s\n", g_params.tagged_msg_id);

  // validating /api/v2/messages/{messageId}
  // Basic outputs
  res_message_t* msg_from_id = res_message_new();
  if (msg_from_id) {
    ret = get_message_by_id(&w->endpoint, g_params.basic_msg_id, msg_from_id);
    if (ret == 0) {
      if (msg_from_id->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, msg_from_id->u.error->msg);
        res_message_free(msg_from_id);
        return -1;
      } else {
        if (g_config.show_payload) {
          core_message_print(msg_from_id->u.msg, 0);
        }
        printf("[%s:%d] GET /api/v2/messages/{messageId}: Basic Outputs PASS\n", __func__, __LINE__);
      }
    } else {
      printf("[%s:%d] performed get_message_by_id failed\n", __func__, __LINE__);
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
    ret = get_message_by_id(&w->endpoint, g_params.milestone_msg_id, msg_from_id);
    if (ret == 0) {
      // milestone ID is not a message
      if (msg_from_id->is_error) {
        printf("[%s:%d] GET /api/v2/messages/{messageId}: Milestone PASS\n", __func__, __LINE__);
      } else {
        printf("[%s:%d] GET /api/v2/messages/{messageId}: Milestone NG\n", __func__, __LINE__);
        res_message_free(msg_from_id);
        return -1;
      }
    } else {
      printf("[%s:%d] performed get_message_by_id failed\n", __func__, __LINE__);
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
    ret = get_message_by_id(&w->endpoint, g_params.tagged_msg_id, msg_from_id);
    if (ret == 0) {
      if (msg_from_id->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, msg_from_id->u.error->msg);
        res_message_free(msg_from_id);
        return -1;
      } else {
        if (g_config.show_payload) {
          core_message_print(msg_from_id->u.msg, 0);
        }
        printf("[%s:%d] GET /api/v2/messages/{messageId}: Tagged Data PASS\n", __func__, __LINE__);
      }
    } else {
      printf("[%s:%d] performed get_message_by_id failed\n", __func__, __LINE__);
      res_message_free(msg_from_id);
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
    ret = get_message_metadata(&w->endpoint, g_params.basic_msg_id, meta);
    if (ret == 0) {
      if (meta->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, meta->u.error->msg);
        msg_meta_free(meta);
        return -1;
      } else {
        if (g_config.show_payload) {
          print_message_metadata(meta, 0);
        }
        printf("[%s:%d] GET /api/v2/messages/{messageId}/metadata: Basic Outputs PASS\n", __func__, __LINE__);
      }
    } else {
      printf("[%s:%d] performed get_message_metadata failed\n", __func__, __LINE__);
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
    ret = get_message_metadata(&w->endpoint, g_params.milestone_msg_id, meta);
    if (ret == 0) {
      // milestone ID is not a message
      if (meta->is_error) {
        printf("[%s:%d] GET /api/v2/messages/{messageId}/metadata: Milestone PASS\n", __func__, __LINE__);
      } else {
        printf("[%s:%d] GET /api/v2/messages/{messageId}/metadata: Milestone NG\n", __func__, __LINE__);
        msg_meta_free(meta);
        return -1;
      }
    } else {
      printf("[%s:%d] performed get_message_metadata failed\n", __func__, __LINE__);
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
    ret = get_message_metadata(&w->endpoint, g_params.tagged_msg_id, meta);
    if (ret == 0) {
      if (meta->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, meta->u.error->msg);
        msg_meta_free(meta);
        return -1;
      } else {
        if (g_config.show_payload) {
          print_message_metadata(meta, 0);
        }
        printf("[%s:%d] GET /api/v2/messages/{messageId}/metadata: Tagged Data PASS\n", __func__, __LINE__);
      }
    } else {
      printf("[%s:%d] performed get_message_metadata failed\n", __func__, __LINE__);
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
    ret = get_message_children(&w->endpoint, g_params.basic_msg_id, msg_child);
    if (ret == 0) {
      if (msg_child->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, msg_child->u.error->msg);
        res_msg_children_free(msg_child);
        return -1;
      } else {
        if (g_config.show_payload) {
          print_message_children(msg_child, 0);
        }
        printf("[%s:%d] GET /api/v2/messages/{messageId}/children: Basic Outputs PASS\n", __func__, __LINE__);
      }
    } else {
      printf("[%s:%d] performed get_message_children failed\n", __func__, __LINE__);
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
    ret = get_message_children(&w->endpoint, g_params.milestone_msg_id, msg_child);
    if (ret == 0) {
      // milestone is not a message
      if (msg_child->is_error) {
        printf("[%s:%d] GET /api/v2/messages/{messageId}/children: Milestone PASS\n", __func__, __LINE__);
      } else {
        printf("[%s:%d] GET /api/v2/messages/{messageId}/children: Milestone NG\n", __func__, __LINE__);
        printf("[%s:%d] https://github.com/gohornet/hornet/issues/1488\n", __func__, __LINE__);
        // res_msg_children_free(msg_child);
        // return -1;
      }
    } else {
      printf("[%s:%d] performed get_message_children failed\n", __func__, __LINE__);
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
    ret = get_message_children(&w->endpoint, g_params.tagged_msg_id, msg_child);
    if (ret == 0) {
      if (msg_child->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, msg_child->u.error->msg);
        res_msg_children_free(msg_child);
        return -1;
      } else {
        if (g_config.show_payload) {
          print_message_children(msg_child, 0);
        }
        printf("[%s:%d] GET /api/v2/messages/{messageId}/children: Tagged Data PASS\n", __func__, __LINE__);
      }
    } else {
      printf("[%s:%d] performed get_message_children failed\n", __func__, __LINE__);
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

static int validating_indexers_basic(iota_wallet_t* w) {
  int ret = 0;
  res_outputs_id_t* res_ids = NULL;

  // get bech32 address as the query paramter
  char bech32_addr[BIN_TO_HEX_STR_BYTES(ADDRESS_MAX_BYTES)] = {};
  if (address_to_bech32(&g_params.sender, g_params.w->bech32HRP, bech32_addr, sizeof(bech32_addr)) != 0) {
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
    ret = get_outputs_id(&g_params.w->endpoint, filter, res_ids);
    if (ret == 0) {
      if (res_ids->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, res_ids->u.error->msg);
        outputs_query_list_free(filter);
        res_outputs_free(res_ids);
        return -1;
      } else {
        // check if there are outputs in this address
        if (res_outputs_output_id_count(res_ids) < 1) {
          printf("[%s:%d] no outputs in this address\n", __func__, __LINE__);
          outputs_query_list_free(filter);
          res_outputs_free(res_ids);
          return -1;
        }
        strncpy(g_params.output_id, res_outputs_output_id(res_ids, 0), sizeof(g_params.output_id));
        printf("[%s:%d] GET /api/plugins/indexer/v1/outputs/basic: PASS\n", __func__, __LINE__);
      }
    } else {
      printf("[%s:%d] performed get_outputs_id failed\n", __func__, __LINE__);
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

static int validating_utxo(iota_wallet_t* w) {
  int ret = 0;
  printf("Testing output ID: 0x%s\n", g_params.basic_msg_id);

  // find an output by its ID
  res_output_t* res_output = get_output_response_new();
  if (res_output) {
    // get the output object
    if (get_output(&g_params.w->endpoint, g_params.output_id, res_output) != 0) {
      printf("[%s:%d] performed get_output failed\n", __func__, __LINE__);
      get_output_response_free(res_output);
      return -1;
    } else {
      if (res_output->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, res_output->u.error->msg);
        get_output_response_free(res_output);
        return -1;
      } else {
        if (g_config.show_payload) {
          dump_get_output_response(res_output, 0);
        }
        printf("[%s:%d] GET /api/v2/outputs/{outputId}: PASS\n", __func__, __LINE__);
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
    if (get_output_meta(&g_params.w->endpoint, g_params.output_id, res_output) != 0) {
      printf("[%s:%d] performed get_output_meta failed\n", __func__, __LINE__);
      get_output_response_free(res_output);
      return -1;
    } else {
      if (res_output->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, res_output->u.error->msg);
        get_output_response_free(res_output);
        return -1;
      } else {
        if (g_config.show_payload) {
          dump_get_output_response(res_output, 0);
        }
        if (bin_2_hex(res_output->u.data->meta.tx_id, IOTA_TRANSACTION_ID_BYTES, NULL, g_params.tx_id,
                      sizeof(g_params.tx_id)) != 0) {
          printf("[%s:%d] convert transaction ID failed\n", __func__, __LINE__);
        } else {
          printf("[%s:%d] GET /api/v2/outputs/{outputId}/meta: PASS\n", __func__, __LINE__);
        }
      }
    }
  } else {
    printf("[%s:%d] allocate output response failed\n", __func__, __LINE__);
    return -1;
  }
  get_output_response_free(res_output);

  printf("Testing transaction ID: 0x%s\n", g_params.tx_id);
  // TODO: should be tested after hoenet alpha11
#if 0
  // transaction included message
  res_message_t* msg = res_message_new();
  if(msg){
    if(get_transaction_included_message_by_id(&g_params.w->endpoint, g_params.tx_id, msg) != 0){
      printf("[%s:%d] performed get_transaction_included_message_by_id failed\n", __func__, __LINE__);
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
        }else{
          printf("[%s:%d] it's not a transaction payload\n", __func__, __LINE__);
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

int main(int argc, char* argv[]) {
  int ret = 0;

  // read config
  if (argc < 2) {
    if (read_config_file("./config.json") != 0) {
      printf("[%s:%d] read config file error\n", __func__, __LINE__);
      return -1;
    }
  } else {
    if (read_config_file(argv[1]) != 0) {
      printf("[%s:%d] read config file error\n", __func__, __LINE__);
      return -1;
    }
  }

  // init paramters
  memset(&g_params, 0, sizeof(test_data_t));

  // try connect to the node
  if (get_info() != 0) {
    printf("[%s:%d] connecting to node failed\n", __func__, __LINE__);
    return -1;
  }

  // wallet init
  if (init_wallet() != 0) {
    printf("[%s:%d] init wallet failed\n", __func__, __LINE__);
    return -1;
  }

  // request tokens for sender
  if (request_token() != 0) {
    printf("[%s:%d] request token from faucet failed\n", __func__, __LINE__);
    wallet_destroy(g_params.w);
    return -1;
  }

  // wait a little bit for getting tokens from faucet
  printf("[%s:%d] waiting for faucet...", __func__, __LINE__);
  sleep(g_config.delay + 10);

  // send basic tx
  // get an valid message ID for messages endpoints test
  if (send_basic_tx() != 0) {
    printf("[%s:%d] send basic tx failed\n", __func__, __LINE__);
    wallet_destroy(g_params.w);
    return -1;
  }

  // wait a little bit for message get confirmed
  printf("[%s:%d] waiting for message confirmation...", __func__, __LINE__);
  sleep(g_config.delay);

  // send tagged message
  // get an valid message ID for messages endpoints test
  if (send_tagged_payload() != 0) {
    printf("[%s:%d] send tagged message failed\n", __func__, __LINE__);
    wallet_destroy(g_params.w);
    return -1;
  }

  // wait a little bit for ledger status update
  printf("[%s:%d] waiting for ledger status update...", __func__, __LINE__);
  sleep(g_config.delay);

  // fetch milestone
  if (fetch_milestone() != 0) {
    printf("[%s:%d] fetch milestone failed\n", __func__, __LINE__);
    wallet_destroy(g_params.w);
    return -1;
  }

  // validate messages endpoints
  if (validating_messages(g_params.w)) {
    printf("[%s:%d] validate message endpoints failed\n", __func__, __LINE__);
    wallet_destroy(g_params.w);
    return -1;
  }

  // validate Indexer endpoints
  // get the testing output ID from indexer for validating UTXO endpoints
  if (validating_indexers_basic(g_params.w)) {
    printf("[%s:%d] validate basic indexer endpoints failed\n", __func__, __LINE__);
    wallet_destroy(g_params.w);
    return -1;
  }

  // validate UTXO endpoints
  if (validating_utxo(g_params.w)) {
    printf("[%s:%d] validate UTXO endpoints failed\n", __func__, __LINE__);
    wallet_destroy(g_params.w);
    return -1;
  }

  wallet_destroy(g_params.w);
  return 0;
}
