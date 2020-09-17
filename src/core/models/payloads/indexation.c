#include <inttypes.h>
#include <stdio.h>

#include "core/models/payloads/indexation.h"

// FixMe: indexation operation in icd.
static UT_icd const indexation_list_icd = {sizeof(indexation_t), NULL, NULL, NULL};

indexation_list_t *indexation_list_new() {
  indexation_list_t *list = NULL;
  utarray_new(list, &indexation_list_icd);
  return list;
}
