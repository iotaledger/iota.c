// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

#include "core/models/message.h"
#include "core/models/payloads/tagged_data.h"
#include "core/utils/macros.h"

tagged_data_t *tagged_data_new() {
  tagged_data_t *tagged_data = malloc(sizeof(tagged_data_t));
  if (tagged_data) {
    tagged_data->tag = NULL;
    tagged_data->data = NULL;
  }
  return tagged_data;
}

void tagged_data_free(tagged_data_t *tagged_data) {
  if (tagged_data) {
    byte_buf_free(tagged_data->tag);
    byte_buf_free(tagged_data->data);
    free(tagged_data);
  }
}

tagged_data_t *tagged_data_create(byte_t tag[], uint8_t tag_len, byte_t data[], uint32_t data_len) {
  if (tag == NULL || (data_len > 0 && data == NULL)) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  if (tag_len > TAGGED_DATA_TAG_MAX_LENGTH_BYTES) {
    printf("[%s:%d] invalid tag\n", __func__, __LINE__);
    return NULL;
  }

  tagged_data_t *tagged_data = tagged_data_new();
  if (!tagged_data) {
    printf("[%s:%d] can not create tagged data object\n", __func__, __LINE__);
    return NULL;
  }

  // add binary tag
  if (tag_len > 0) {
    tagged_data->tag = byte_buf_new_with_data(tag, tag_len);
    if (!tagged_data->tag) {
      printf("[%s:%d] adding tag to a tagged data failed\n", __func__, __LINE__);
      tagged_data_free(tagged_data);
      return NULL;
    }
  }

  // add binary data
  if (data_len > 0) {
    tagged_data->data = byte_buf_new_with_data(data, data_len);
    if (!tagged_data->data) {
      printf("[%s:%d] adding data to a tagged data failed\n", __func__, __LINE__);
      tagged_data_free(tagged_data);
      return NULL;
    }
  }

  return tagged_data;
}

size_t tagged_data_serialize_len(tagged_data_t *tagged_data) {
  if (tagged_data == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  size_t length = 0;

  // payload type
  length += sizeof(uint32_t);
  // tag length
  length += sizeof(uint8_t);
  // tag
  if (tagged_data->tag) {
    length += tagged_data->tag->len;
  }
  // binary data length
  length += sizeof(uint32_t);
  // binary data
  if (tagged_data->data) {
    length += tagged_data->data->len;
  }

  return length;
}

size_t tagged_data_serialize(tagged_data_t *tagged_data, byte_t buf[], size_t buf_len) {
  if (tagged_data == NULL || buf == NULL || buf_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  size_t expected_bytes = tagged_data_serialize_len(tagged_data);
  if (buf_len < expected_bytes) {
    printf("[%s:%d] buffer size is insufficient\n", __func__, __LINE__);
    return 0;
  }

  size_t offset = 0;

  // fill-in Tagged Data type
  uint32_t payload_type = CORE_MESSAGE_PAYLOAD_TAGGED;
  memcpy(buf, &payload_type, sizeof(uint32_t));
  offset += sizeof(uint32_t);

  if (tagged_data->tag) {
    // tag length
    memcpy(buf + offset, &tagged_data->tag->len, sizeof(uint8_t));
    offset += sizeof(uint8_t);

    // tag
    if (tagged_data->tag->len > 0) {
      memcpy(buf + offset, tagged_data->tag->data, tagged_data->tag->len);
      offset += tagged_data->tag->len;
    }
  } else {
    // tag length is zero
    memset(buf + offset, 0, sizeof(uint8_t));
    offset += sizeof(uint8_t);
  }

  if (tagged_data->data) {
    // binary data length
    memcpy(buf + offset, &tagged_data->data->len, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    // binary data
    if (tagged_data->data->len > 0) {
      memcpy(buf + offset, tagged_data->data->data, tagged_data->data->len);
      offset += tagged_data->data->len;
    }
  } else {
    // binary data length is zero
    memset(buf + offset, 0, sizeof(uint32_t));
    offset += sizeof(uint32_t);
  }

  return offset;
}

tagged_data_t *tagged_data_deserialize(byte_t buf[], size_t buf_len) {
  if (buf == NULL || buf_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  tagged_data_t *tagged_data = tagged_data_new();
  if (!tagged_data) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return NULL;
  }

  size_t offset = 0;

  // output type
  if (buf_len < offset + sizeof(uint32_t)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    tagged_data_free(tagged_data);
    return NULL;
  }
  if ((uint32_t)buf[offset] != CORE_MESSAGE_PAYLOAD_TAGGED) {
    printf("[%s:%d] buffer does not contain tagged data object\n", __func__, __LINE__);
    tagged_data_free(tagged_data);
    return NULL;
  }
  offset += sizeof(uint32_t);

  // tag length
  if (buf_len < offset + sizeof(uint8_t)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    tagged_data_free(tagged_data);
    return NULL;
  }
  uint8_t tag_length = 0;
  memcpy(&tag_length, &buf[offset], sizeof(uint8_t));
  offset += sizeof(uint8_t);

  // tag
  if (tag_length > 0) {
    if (buf_len < offset + tag_length) {
      printf("[%s:%d] invalid data length\n", __func__, __LINE__);
      tagged_data_free(tagged_data);
      return NULL;
    }
    tagged_data->tag = byte_buf_new_with_data(&buf[offset], tag_length);
    if (!tagged_data->tag) {
      printf("[%s:%d] can not add tag data to a tagged data\n", __func__, __LINE__);
      tagged_data_free(tagged_data);
      return NULL;
    }
    offset += tag_length;
  }

  // binary data length
  if (buf_len < offset + sizeof(uint32_t)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    tagged_data_free(tagged_data);
    return NULL;
  }
  uint32_t data_length = 0;
  memcpy(&data_length, &buf[offset], sizeof(uint32_t));
  offset += sizeof(uint32_t);

  // binary data
  if (data_length > 0) {
    if (buf_len < offset + data_length) {
      printf("[%s:%d] invalid data length\n", __func__, __LINE__);
      tagged_data_free(tagged_data);
      return NULL;
    }
    tagged_data->data = byte_buf_new_with_data(&buf[offset], data_length);
    if (!tagged_data->data) {
      printf("[%s:%d] can not add binary data to a tagged data\n", __func__, __LINE__);
      tagged_data_free(tagged_data);
      return NULL;
    }
  }

  return tagged_data;
}

void tagged_data_print(tagged_data_t *tagged_data, uint8_t indentation) {
  if (tagged_data == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return;
  }

  printf("%sTagged Data:\n", PRINT_INDENTATION(indentation));

  // tag
  if (tagged_data->tag) {
    printf("%s\tTag: ", PRINT_INDENTATION(indentation));
    dump_hex_str(tagged_data->tag->data, tagged_data->tag->len);
  } else {
    printf("%s\tTag:\n", PRINT_INDENTATION(indentation));
  }

  // binary data
  if (tagged_data->data) {
    printf("%s\tData: ", PRINT_INDENTATION(indentation));
    dump_hex_str(tagged_data->data->data, tagged_data->data->len);
  } else {
    printf("%s\tData:\n", PRINT_INDENTATION(indentation));
  }
}
