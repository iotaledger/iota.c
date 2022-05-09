// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_CONSTANTS_H__
#define __CLIENT_CONSTANTS_H__

#include "core/constants.h"

#define NODE_API_PATH "/api/v2"

#define IOTA_ENDPOINT_MAX_LEN 256

/***** Defines related to Node Events *****/
#define TOPIC_MILESTONE_LATEST "milestone-info/latest"
#define TOPIC_MILESTONE_CONFIRMED "milestone-info/confirmed"
#define TOPIC_MILESTONES "milestones"
#define TOPIC_MS_REFERENCED "message-metadata/referenced"
#define TOPIC_MESSAGES "messages"
#define TOPIC_MS_TRANSACTION "messages/transaction"
#define TOPIC_MS_TXN_TAGGED_DATA "messages/transaction/tagged-data"
#define TOPIC_MS_MILESTONE "messages/milestone"
#define TOPIC_MS_TAGGED_DATA "messages/tagged-data"

#endif
