#include <stdio.h>
#include <stdlib.h>

#include "client/api/get_message_hash.h"

res_msg_t *res_msg_new() {
  res_msg_t *msg = malloc(sizeof(res_msg_t));
  msg->is_error = false;
  return msg;
}

void res_msg_free(res_msg_t *msg) {
  if (msg) {
    if (msg->is_error) {
      res_err_free(msg->msg_u.error);
    } else {
      // TODO: free message object
    }
    free(msg);
  }
}

int deser_message_payload(char const *const j_str, res_msg_t *msg) {
  int ret = 0;
  cJSON *json_obj = cJSON_Parse(j_str);
  if (json_obj == NULL) {
    return -1;
  }

  res_err_t *res_err = deser_error(json_obj);
  if (res_err) {
    // got an error response
    msg->is_error = true;
    msg->msg_u.error = res_err;
    ret = 0;
    goto end;
  }

  // TODO: deser message
  cJSON *data_obj = cJSON_GetObjectItemCaseSensitive(json_obj, key_data);
  if (data_obj) {
  }

end:
  cJSON_Delete(json_obj);
  return ret;
}