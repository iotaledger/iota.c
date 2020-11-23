
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/utils/iota_str.h"
#include "core/utils/slip10.h"

// ParsePath parses s as a BIP-32 path, returning the result.
// The string s can be in the form where the apostrophe means hardened key ("m/44'/0'/0'/0/0")
// or where "H" means hardened key ("m/44H/0H/0H/0/0"). The "m/" prefix is mandatory.
int slip10_parse_path(char str[], uint32_t path[]) {
  if (strlen(str) < 2) {
    return -1;
  }

  if (str[0] != 'm' && str[1] != '/') {
    // "m/" prefix is mandatory.
    return -1;
  }

  if (strstr(str, "//") != NULL || strstr(str, "''") != NULL || strstr(str, "'H") != NULL ||
      strstr(str, "H'") != NULL || strstr(str, "HH") != NULL || strstr(str, "h") != NULL) {
    // invalid path format
    return -1;
  }

  int ret = 0;
  iota_str_t* path_buf = iota_str_new(str + 2);
  char* token = strtok(path_buf->buf, "/");
  int i = 0;
  while (token != NULL) {
    char* ptr = NULL;
    // check token format
    if (strncmp(token, "\'", 1) == 0 || strncmp(token, "H", 1) == 0) {
      // invalid format
      ret = -1;
      goto end;
    }

    // get value
    unsigned long value = strtoul(token, &ptr, 10);
    if (value >= BIP32_HARDENED) {
      // out of range
      ret = -2;
      goto end;
    }

    // hardened
    if (strncmp(ptr, "\'", 1) == 0 || strncmp(ptr, "H", 1) == 0) {
      value |= BIP32_HARDENED;
    }
    path[i] = value;

    // gets next token
    token = strtok(NULL, "/");
    i++;
  }
end:
  iota_str_destroy(path_buf);
  return ret;
}
