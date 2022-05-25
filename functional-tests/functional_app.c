#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "client/api/json_parser/json_utils.h"
#include "functional_cases.h"

/**
 * @brief list all test cases and inital state
 *
 */
test_item_t test_cases[MAX_TEST_CASE] = {
    // node
    {CORE_GET_NODE_INFO, "GET /api/v2/info", STATE_NA},
    {CORE_GET_TIPS, "GET /api/v2/tips", STATE_NA},
    // Blocks
    {CORE_POST_BASIC_MSG, "POST /api/v2/messages Basic", STATE_NA},
    {CORE_POST_TAGGED_MSG, "POST /api/v2/messages Tagged", STATE_NA},
    {CORE_GET_MSG_MILESTONE, "GET /api/v2/messages/{messageId} Milestone", STATE_NA},
    {CORE_GET_MSG_BASIC, "GET /api/v2/messages/{messageId} Basic", STATE_NA},
    {CORE_GET_MSG_TAGGED, "GET /api/v2/messages/{messageId} Tagged", STATE_NA},
    {CORE_GET_MSG_META_MILESTONE, "GET /api/v2/messages/{messageId}/metadata Milestone", STATE_NA},
    {CORE_GET_MSG_META_BASIC, "GET /api/v2/messages/{messageId}/metadata Basic", STATE_NA},
    {CORE_GET_MSG_META_TAGGED, "GET /api/v2/messages/{messageId}/metadata Tagged", STATE_NA},
    {CORE_GET_MSG_CHILD_MILESTONE, "GET /api/v2/messages/{messageId}/children Miletone", STATE_NA},
    {CORE_GET_MSG_CHILD_BASIC, "GET /api/v2/messages/{messageId}/children Basic", STATE_NA},
    {CORE_GET_MSG_CHILD_TAGGED, "GET /api/v2/messages/{messageId}/children Tagged", STATE_NA},
    // UTXO
    {CORE_GET_OUTPUTS, "GET /api/v2/outputs/{outputId}", STATE_NA},
    {CORE_GET_OUTPUTS_METADATA, "GET /api/v2/outputs/{outputId}/metadata", STATE_NA},
    {CORE_GET_RECEIPTS, "GET /api/v2/receipts", STATE_NOT_SUPPORT},
    {CORE_GET_RECEIPTS_MIGRATED, "GET /api/v2/receipts/{migratedAt}", STATE_NOT_SUPPORT},
    {CORE_GET_TREASURY, "GET /api/v2/treasury", STATE_NOT_SUPPORT},
    {CORE_GET_TX_INC_MSG, "GET /api/v2/transactions/{transactionId}/included-message", STATE_NA},
    // Milestones
    {CORE_GET_MILESTONES, "GET /api/v2/milestones/{milestoneId}", STATE_NA},
    {CORE_GET_MILESTONES_UTXO, "GET /api/v2/milestones/{milestoneId}/utxo-changes", STATE_NA},
    {CORE_GET_MILESTONES_INDEX, "GET /api/v2/milestones/by-index/{index}", STATE_NA},
    {CORE_GET_MILESTONES_INDEX_UTXO, "GET /api/v2/milestones/by-index/{index}/utxo-changes", STATE_NA},
    // Indexer
    {INDEXER_GET_BASIC, "GET /api/plugins/indexer/v1/outputs/basic", STATE_NA},
    {INDEXER_GET_ALIAS, "GET /api/plugins/indexer/v1/outputs/alias", STATE_NA},
    {INDEXER_GET_ALIAS_ID, "GET /api/plugins/indexer/v1/outputs/alias/{aliasId}", STATE_NA},
    {INDEXER_GET_FOUNDRY, "GET /api/plugins/indexer/v1/outputs/foundry", STATE_NA},
    {INDEXER_GET_FOUNDRY_ID, "GET /api/plugins/indexer/v1/outputs/foundry/{foundryId}", STATE_NA},
    {INDEXER_GET_NFT, "GET /api/plugins/indexer/v1/outputs/nft", STATE_NA},
    {INDEXER_GET_NFT_ID, "GET /api/plugins/indexer/v1/outputs/nft/{nftId}", STATE_NA},
    // faucet
    {FAUCET_GET_ENQUEUE, "GET Faucet enqueue", STATE_NA}};

// global parameters and configurations for functional test
test_data_t g_params;
test_config_t g_config;

static char const* const status_str(test_state_e st) {
  switch (st) {
    case STATE_NOT_SUPPORT:
      return "NotSupport";
    case STATE_NG:
      return "NoGood";
    case STATE_PASS:
      return "PASS";
    case STATE_NA:
    default:
      return "N/A";
  }
}

static void print_test_item(test_item_t* tests) {
  if (tests) {
    printf("Not Supported:\n");
    for (uint32_t i = CORE_GET_NODE_INFO; i < MAX_TEST_CASE; i++) {
      if (tests[i].st == STATE_NOT_SUPPORT) {
        printf("\t%s\n", tests[i].name);
      }
    }
    printf("PASSED:\n");
    for (uint32_t i = CORE_GET_NODE_INFO; i < MAX_TEST_CASE; i++) {
      if (tests[i].st == STATE_PASS) {
        printf("\t%s\n", tests[i].name);
      }
    }
    printf("Not Available:\n");
    for (uint32_t i = CORE_GET_NODE_INFO; i < MAX_TEST_CASE; i++) {
      if (tests[i].st == STATE_NA) {
        printf("\t%s\n", tests[i].name);
      }
    }
    printf("No Good:\n");
    for (uint32_t i = CORE_GET_NODE_INFO; i < MAX_TEST_CASE; i++) {
      if (tests[i].st == STATE_NG) {
        printf("\t%s\n", tests[i].name);
      }
    }
  }
}

static void dump_test_config(test_config_t* config) {
  if (config) {
    printf("Mnemonic: \"%s\"\n", config->mnemonic);
    printf("Sender Address Index: %u\n", config->sender_index);
    printf("Receiver Address Index: %u\n", config->receiver_index);
    printf("Node: %s:%d tls: %s\n", config->node_config.host, config->node_config.port,
           config->node_config.use_tls ? "true" : "false");
    printf("Faucet: %s:%d tls: %s\n", config->faucet_config.host, config->faucet_config.port,
           config->faucet_config.use_tls ? "true" : "false");
    printf("Show payload: %s\n", config->show_payload ? "true" : "false");
    printf("Coin Type: %" PRIu32 "\n", config->coin_type);
    printf("Delay: %d\n", config->delay);
  }
}

static void dump_test_params(test_data_t* params) {
  char bech32_tmp[BIN_TO_HEX_STR_BYTES(ADDRESS_MAX_BYTES)] = {};

  if (params) {
    if (params->w) {
      printf("Basic Sender: \n\t");
      address_print(&params->sender);
      if (address_to_bech32(&params->sender, params->w->bech32HRP, bech32_tmp, sizeof(bech32_tmp)) == 0) {
        printf("\t%s\n", bech32_tmp);
      }
      printf("Basic Receiver: \n\t");
      address_print(&params->recv);
      if (address_to_bech32(&params->recv, params->w->bech32HRP, bech32_tmp, sizeof(bech32_tmp)) == 0) {
        printf("\t%s\n", bech32_tmp);
      }
    }

    if (!buf_all_zeros((uint8_t*)params->basic_blk_id, sizeof(params->basic_blk_id))) {
      printf("Basic Block ID: 0x%s\n", params->basic_blk_id);
    }
    if (!buf_all_zeros((uint8_t*)params->milestone_blk_id, sizeof(params->milestone_blk_id))) {
      printf("Milestone ID: 0x%s\n", params->milestone_blk_id);
    }
    if (!buf_all_zeros((uint8_t*)params->tagged_blk_id, sizeof(params->tagged_blk_id))) {
      printf("Tagged Block ID: 0x%s\n", params->tagged_blk_id);
    }
    if (!buf_all_zeros((uint8_t*)params->output_id, sizeof(params->output_id))) {
      printf("Output ID: 0x%s\n", params->output_id);
    }
    if (!buf_all_zeros((uint8_t*)params->tx_id, sizeof(params->tx_id))) {
      printf("Transaction ID: 0x%s\n", params->tx_id);
    }
  }
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

  // coin type
  if ((ret = json_get_uint32(config_obj, "coin_type", &g_config.coin_type)) != 0) {
    printf("[%s:%d] get coin type failed\n", __func__, __LINE__);
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

  free(file_buf);
  return 0;
}

static void summary() {
  printf("=========Test Config==========\n");
  dump_test_config(&g_config);
  printf("=========Test Paramters=======\n");
  dump_test_params(&g_params);
  printf("=========Test Status==========\n");
  print_test_item(test_cases);
}

int main(int argc, char* argv[]) {
  int ret = 0;

  // read config
  if (argc < 2) {
    if ((ret = read_config_file("./config.json")) != 0) {
      printf("[%s:%d] read config file error\n", __func__, __LINE__);
      return ret;
    }
  } else {
    if ((ret = read_config_file(argv[1])) != 0) {
      printf("[%s:%d] read config file error\n", __func__, __LINE__);
      return ret;
    }
  }

  // init paramters
  memset(&g_params, 0, sizeof(test_data_t));

  if (restful_api_tests(&g_config, &g_params, test_cases) != 0) {
    printf("[%s:%d] restful API test failed\n", __func__, __LINE__);
  }

  summary();
  wallet_destroy(g_params.w);
  return ret;
}
