#include <stdio.h>
#include <string.h>
#include <unistd.h>  // for Linux sleep()

#include "cJSON.h"

#include "client/api/restful/faucet_enqueue.h"
#include "client/api/restful/get_message.h"
#include "client/api/restful/get_message_metadata.h"
#include "client/api/restful/get_milestone.h"
#include "client/api/restful/response_error.h"
#include "client/api/restful/send_tagged_data.h"
#include "core/address.h"
#include "core/models/message.h"
#include "core/models/payloads/milestone.h"
#include "core/utils/byte_buffer.h"
#include "core/utils/macros.h"
#include "wallet/wallet.h"

static char const* const test_mnemonic =
    "acoustic trophy damage hint search taste love bicycle foster cradle brown govern endless depend situate athlete "
    "pudding blame question genius transfer van random vast";

iota_wallet_t* g_w = NULL;

char g_basic_msg_id[BIN_TO_HEX_STR_BYTES(IOTA_MESSAGE_ID_BYTES)];
char g_milestone_msg_id[BIN_TO_HEX_STR_BYTES(IOTA_MESSAGE_ID_BYTES)];
char g_tagged_data_msg_id[BIN_TO_HEX_STR_BYTES(IOTA_MESSAGE_ID_BYTES)];

address_t g_sender;
address_t g_receiver;

static int init_wallet() {
  int ret = 0;
  g_w = wallet_create(test_mnemonic, "", 0);
  if (!g_w) {
    printf("[%s:%d] wallet create failed\n", __func__, __LINE__);
    return -1;
  }

  ret = wallet_set_endpoint(g_w, "localhost", 14265, false);
  if (ret != 0) {
    printf("[%s:%d] wallet set endpoint failed\n", __func__, __LINE__);
    wallet_destroy(g_w);
    return -1;
  }

  // validating /api/v2/info
  ret = wallet_update_node_config(g_w);
  if (ret != 0) {
    printf("[%s:%d] wallet get node info failed\n", __func__, __LINE__);
    wallet_destroy(g_w);
    return -1;
  }
  printf("[%s:%d] GET /api/v2/info: PASS\n", __func__, __LINE__);
  return 0;
}

static int request_token() {
  int ret = 0;
  iota_client_conf_t ctx = {.host = "localhost", .port = 8091, .use_tls = false};
  res_faucet_enqueue_t res = {};
  char sender_bech32[BIN_TO_HEX_STR_BYTES(ADDRESS_MAX_BYTES)] = {};

  ret = wallet_ed25519_address_from_index(g_w, false, 0, &g_sender);
  if (ret != 0) {
    printf("[%s:%d] derive sender address failed\n", __func__, __LINE__);
    return -1;
  }

  ret = address_to_bech32(&g_sender, g_w->bech32HRP, sender_bech32, sizeof(sender_bech32));
  if (ret != 0) {
    printf("[%s:%d] get bech32 address failed\n", __func__, __LINE__);
    return -1;
  }

  // Test bech32 address with invalid len
  ret = req_tokens_to_addr_from_faucet(&ctx, sender_bech32, &res);
  if (ret == 0) {
    if (res.is_error == true) {
      printf("[%s:%d] request token err: %s\n", __func__, __LINE__, res.u.error->msg);
      return -1;
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

  ret = wallet_ed25519_address_from_index(g_w, false, 0, &g_receiver);
  if (ret != 0) {
    printf("[%s:%d] derive receiver address failed\n", __func__, __LINE__);
    return -1;
  }

  // wait a little bit for getting tokens from faucet
  sleep(10);

  // validating /api/v2/tips and /api/v2/message with basic outputs
  // send 1Mi to reciver
  ret = wallet_send_basic_outputs(g_w, false, 0, &g_receiver, 1000000, &msg_res);
  if (ret == 0) {
    if (msg_res.is_error) {
      printf("[%s:%d] Error: %s\n", __func__, __LINE__, msg_res.u.error->msg);
      res_err_free(msg_res.u.error);
      return -1;
    } else {
      strncpy(g_basic_msg_id, msg_res.u.msg_id, BIN_TO_HEX_STR_BYTES(IOTA_MESSAGE_ID_BYTES));
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

  ret = send_tagged_data_message(&g_w->endpoint, g_w->protocol_version, tag, sizeof(tag), tag_data, sizeof(tag_data),
                                 &res);
  if (ret == 0) {
    if (res.is_error) {
      printf("[%s:%d]Err: %s\n", __func__, __LINE__, res.u.error->msg);
      res_err_free(res.u.error);
      return -1;
    } else {
      strncpy(g_tagged_data_msg_id, res.u.msg_id, BIN_TO_HEX_STR_BYTES(IOTA_MESSAGE_ID_BYTES));
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
    ret = get_milestone_by_index(&g_w->endpoint, 2, res_ml);
    if (ret == 0) {
      if (res_ml->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, res_ml->u.error->msg);
        res_milestone_free(res_ml);
        return -1;
      } else {
        // milestone_payload_print(res_ml->u.ms, 0);
        bin_2_hex(res_ml->u.ms->previous_milestone_id, sizeof(res_ml->u.ms->previous_milestone_id), NULL,
                  g_milestone_msg_id, sizeof(g_milestone_msg_id));
        printf("[%s:%d] Milestone ID: %s\n", __func__, __LINE__, g_milestone_msg_id);
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
    ret = get_milestone_by_id(&g_w->endpoint, g_milestone_msg_id, res_ml);
    if (ret == 0) {
      if (res_ml->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, res_ml->u.error->msg);
        res_milestone_free(res_ml);
        return -1;
      } else {
        // milestone_payload_print(res_ml->u.ms, 0);
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
    ret = get_utxo_changes_by_ms_index(&g_w->endpoint, 2, res_ml_utxo);
    if (ret == 0) {
      if (res_ml_utxo->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, res_ml_utxo->u.error->msg);
        res_utxo_changes_free(res_ml_utxo);
        return -1;
      } else {
        // print_utxo_changes(res_ml_utxo, 0);
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
    ret = get_utxo_changes_by_ms_id(&g_w->endpoint, g_milestone_msg_id, res_ml_utxo);
    if (ret == 0) {
      if (res_ml_utxo->is_error) {
        printf("[%s:%d] Err: %s\n", __func__, __LINE__, res_ml_utxo->u.error->msg);
        res_utxo_changes_free(res_ml_utxo);
        return -1;
      } else {
        // print_utxo_changes(res_ml_utxo, 0);
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
  // validating /api/v2/messages/{messageId}
  res_message_t* msg_from_id = res_message_new();
  if (msg_from_id) {
    ret = get_message_by_id(&w->endpoint, g_basic_msg_id, msg_from_id);
    if (ret == 0) {
      core_message_print(msg_from_id->u.msg, 0);
      printf("[%s:%d] GET /api/v2/messages/{messageId}: PASS\n", __func__, __LINE__);
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
    ret = get_message_metadata(&w->endpoint, g_basic_msg_id, meta);
    if (ret == 0) {
      printf("[%s:%d] get_message_metadata PASS\n", __func__, __LINE__);
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

  return 0;
}

int main() {
  int ret = 0;
  // TODO read config

  // wallet init
  if (init_wallet() != 0) {
    printf("[%s:%d] init wallet failed\n", __func__, __LINE__);
    return -1;
  }

  // request tokens for sender
  if (request_token() != 0) {
    printf("[%s:%d] request token from faucet failed\n", __func__, __LINE__);
    wallet_destroy(g_w);
    return -1;
  }

  // send basic tx
  if (send_basic_tx() != 0) {
    printf("[%s:%d] send basic tx failed\n", __func__, __LINE__);
    wallet_destroy(g_w);
    return -1;
  }

  // send tagged message
  if (send_tagged_payload() != 0) {
    printf("[%s:%d] send tagged message failed\n", __func__, __LINE__);
    wallet_destroy(g_w);
    return -1;
  }

  // fetch milestone
  if (fetch_milestone() != 0) {
    printf("[%s:%d] fetch milestone failed\n", __func__, __LINE__);
    wallet_destroy(g_w);
    return -1;
  }

  // validate core restful APIs
  // validating_messages(g_w);

  wallet_destroy(g_w);
  return 0;
}
