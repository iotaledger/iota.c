#[[
// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
]]

if(IOTA_WALLET_ENABLE)
	add_subdirectory(wallet)
endif(IOTA_WALLET_ENABLE)

if(WITH_IOTA_CLIENT)
	add_subdirectory(client)
endif()

if(WITH_IOTA_CORE)
	add_subdirectory(core)
endif()

add_subdirectory(crypto)